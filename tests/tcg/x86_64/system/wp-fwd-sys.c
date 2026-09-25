/*
 * Wrong-path store-to-load forwarding victim, softmmu form: a bare-metal
 * x86_64 kernel for the wp-assert plugin (test FWD_SHAPES, fwd=on).
 *
 * One trigger drives one excursion whose wrong path (wp_fwd) stores into a
 * six-page buffer through r13 and loads the same bytes back through rdx,
 * one shape per load: in-page and page-crossing loads of 2, 4, 8 and 16
 * bytes, and MOVBE loads of 2, 4 and 8 bytes.  The plugin reads each
 * load's result from the wrong path's registers and compares it with the
 * buffer's real bytes overlaid with the shape's stores (the shape table in
 * tests/tcg/plugins/wp-assert.c mirrors wp_fwd; keep them in sync).
 *
 * The kernel then resets the machine once through the ICH9 reset control
 * register, remembering in CMOS that it did, and on the second boot powers
 * off through ACPI (boot.S), so a plugin run with w2=on sees one reset and
 * one shutdown callback.
 *
 * Needs: -M q35 -cpu max (MOVBE) -device isa-debugcon,chardev=output
 *        -device isa-debug-exit,iobase=0xf4,iosize=0x4
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <stdint.h>
#include <stdbool.h>
#include <minilib.h>

#define FWD_SHAPES 25           /* keep in sync with wp-assert.c */
#define FWD_BUF_LEN 0x6000
#define CMOS_FLAG 0x7e          /* a CMOS byte QEMU's q35 leaves unused */
#define CMOS_MAGIC 0x5a

extern void wp_ftrigger(uint64_t test, uint64_t target, void *buf,
                        uint64_t len);
extern char wp_fwd[];

__asm__(
    ".text\n"
    /*
     * void wp_ftrigger(test=rdi, target=rsi, buf=rdx, len=rcx)
     * r13 carries the buffer as the wrong path's store base.
     */
    ".globl wp_ftrigger\n"
    ".p2align 4\n"
    "wp_ftrigger:\n"
    "  push %r13\n"
    "  mov %rdx, %r13\n"
    "  movabs $0x5750415353455254, %r11\n"   /* the marker */
    "  pop %r13\n"
    "  ret\n"

    /* wrong-path only: stores through r13, loads through rdx */
    ".p2align 12\n"
    ".globl wp_fwd\n"
    "wp_fwd:\n"
    "  movabs $0x1122334455667788, %rax\n"
    "  movabs $0x99aabbccdd0fff01, %r14\n"
    "  mov %rax, 0x5100(%r13)\n"             /* LD16_INPAGE  (D1) */
    "  movdqu 0x5100(%rdx), %xmm1\n"
    "  mov %rax, 0x0ffc(%r13)\n"             /* LD8_XPAGE    (D1) */
    "  mov 0x0ffc(%rdx), %rbx\n"
    "  mov %eax, 0x1ffe(%r13)\n"             /* LD4_XPAGE    (D1) */
    "  mov 0x1ffe(%rdx), %ecx\n"
    "  mov %rax, 0x2ff4(%r13)\n"             /* LD16_XPAGE12 (D1) */
    "  mov %r14, 0x2ffc(%r13)\n"
    "  movdqu 0x2ff4(%rdx), %xmm2\n"
    "  mov %rax, 0x5200(%r13)\n"             /* LD8_INPAGE   (control) */
    "  mov 0x5200(%rdx), %rsi\n"
    "  mov %rax, 0x3ff8(%r13)\n"             /* LD16_XPAGE8  (control) */
    "  mov %r14, 0x4000(%r13)\n"
    "  movdqu 0x3ff8(%rdx), %xmm3\n"
    "  mov %ax, 0x4fff(%r13)\n"              /* LD2_XPAGE    (control) */
    "  movzwl 0x4fff(%rdx), %edi\n"
    "  mov %rax, 0x5300(%r13)\n"             /* MOVBE8       (D2) */
    "  movbe 0x5300(%rdx), %r8\n"
    "  mov %eax, 0x5340(%r13)\n"             /* MOVBE4       (D2) */
    "  movbe 0x5340(%rdx), %r9d\n"
    "  xor %r10d, %r10d\n"
    "  mov %ax, 0x5380(%r13)\n"              /* MOVBE2       (D2) */
    "  movbe 0x5380(%rdx), %r10w\n"
    "  movbe 0x53c0(%rdx), %r12\n"           /* MOVBE8_NOFWD (control) */
    "1: jmp 1b\n"
    ".p2align 12\n"
);

static uint8_t fbuf[FWD_BUF_LEN] __attribute__((aligned(4096)));

static inline void outb(uint16_t p, uint8_t v)
{
    __asm__ volatile("outb %0, %1" : : "a"(v), "Nd"(p));
}

static inline uint8_t inb(uint16_t p)
{
    uint8_t v;
    __asm__ volatile("inb %1, %0" : "=a"(v) : "Nd"(p));
    return v;
}

static inline uint64_t read_cr(int n)
{
    uint64_t v = 0;
    if (n == 0) {
        __asm__ volatile("mov %%cr0, %0" : "=r"(v));
    } else {
        __asm__ volatile("mov %%cr4, %0" : "=r"(v));
    }
    return v;
}

static inline void write_cr0(uint64_t v)
{
    __asm__ volatile("mov %0, %%cr0" : : "r"(v) : "memory");
}

static inline void write_cr4(uint64_t v)
{
    __asm__ volatile("mov %0, %%cr4" : : "r"(v) : "memory");
}

static uint8_t cmos_rd(uint8_t idx)
{
    outb(0x70, idx);
    return inb(0x71);
}

static void cmos_wr(uint8_t idx, uint8_t v)
{
    outb(0x70, idx);
    outb(0x71, v);
}

static void setup_sse(void)
{
    uint64_t cr0 = read_cr(0);
    cr0 &= ~(1ull << 2);       /* EM */
    cr0 |= 1ull << 1;          /* MP */
    write_cr0(cr0);
    write_cr4(read_cr(4) | (3ull << 9));   /* OSFXSR | OSXMMEXCPT */
    __asm__ volatile("fninit");
}

static uint64_t buf_sum(void)
{
    uint64_t h = 0xcbf29ce484222325ull;
    for (int i = 0; i < FWD_BUF_LEN; i++) {
        h = (h ^ fbuf[i]) * 0x100000001b3ull;
    }
    return h;
}

int main(void)
{
    if (cmos_rd(CMOS_FLAG) == CMOS_MAGIC) {
        cmos_wr(CMOS_FLAG, 0);
        ml_printf("[wp-fwd-sys] second boot after the guest reset\n");
        ml_printf("[wp-fwd-sys] done\n");
        return 0;              /* boot.S: ACPI poweroff */
    }
    setup_sse();
    for (int i = 0; i < FWD_BUF_LEN; i++) {
        fbuf[i] = 0xee;
    }
    /* MOVBE8_NOFWD's real bytes: no store forwards into them */
    for (int i = 0; i < 8; i++) {
        fbuf[0x53c0 + i] = (uint8_t)(i + 1);
    }
    uint64_t s0 = buf_sum();
    wp_ftrigger(FWD_SHAPES, (uint64_t)wp_fwd, fbuf, sizeof(fbuf));
    ml_printf("[wp-fwd-sys] buffer %s after the excursion\n",
              buf_sum() == s0 ? "intact" : "CHANGED");
    ml_printf("[wp-fwd-sys] resetting through 0xcf9\n");
    cmos_wr(CMOS_FLAG, CMOS_MAGIC);
    outb(0xcf9, 0x02);
    outb(0xcf9, 0x06);         /* ICH9 RCR: hard reset */
    for (;;) {
        __asm__ volatile("hlt");
    }
}
