/*
 * Wrong-path victim, softmmu form: a bare-metal x86_64 kernel for the
 * wp-assert plugin (phase 2).
 *
 * Boots through tests/tcg/x86_64/system/boot.S (PVH, long mode, identity
 * map of the low 4 GiB in 2 MiB pages) under qemu-system-x86_64 -M q35
 * -kernel, and drives the same marker trigger as the linux-user victim
 * (wp_trigger + movabs $WP_MAGIC,%r11, byte for byte), so the phase-1 tests
 * T1-T5 re-run with the real MMU and the TLB-routed speculative store
 * buffer.  On top of those it runs the three phase-2 families of
 * cst_runs/rebuild/wp_tests/WP_TESTS.md ("Softmmu phase 2 design"):
 *
 *   P2-A  clock-freeze invariance: rdtsc around the trigger (A2) and a
 *         wrong-path rdtsc pair (A3); a periodic-timer liveness phase
 *   P2-B  interrupt window: LAPIC one-shot timers armed across the trigger,
 *         a pending-and-masked interrupt the wrong path unmasks, and a
 *         trigger from inside the timer ISR
 *   P2-C  containment: MMIO / port I/O (C1), TLB (C2), CPL0 faults in an
 *         IDT-less window (C3), a page-table walk through MMIO (C4)
 *
 * The kernel installs its own IDT: every vector is counted and logged with
 * the interrupted RIP.  An exception nobody expected is a leaked wrong-path
 * fault and ends the run (the softmmu form of the linux-user signal
 * handlers).  Everything the kernel prints (isa-debugcon) is a function of
 * the correct path alone, so under -icount it must be byte-identical with
 * and without the plugin's excursions.  Paths that depend on host time
 * (the TSC deltas) are printed on "[p2a]" lines the runner compares
 * numerically rather than byte for byte.
 *
 * Needs: -M q35 -device e1000 -device isa-debug-exit,iobase=0xf4,iosize=0x4
 *        -device isa-debugcon,chardev=output and a COM1 serial backend.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <stdint.h>
#include <stdbool.h>
#include <minilib.h>

/* Keep in sync with tests/tcg/plugins/wp-assert.c */
enum {
    T1_STORE = 1, T1_RO, T2_REGS, T3_FETCH_UNMAPPED, T3_STRADDLE, T3_UD,
    T3_DIV0, T3_PRIV, T3_INT3, T3_LOAD_UNMAPPED, T3_SYSCALL, T4_LOOP,
    T4_REP, T5_REPEAT,
    P2A_CLOCK, P2B_TIMER, P2B_PEND, P2B_ISR, C1_MMIO, C2_TLB, C3_GP,
    C3_PF, C3_UD, C4_PTW,
    T_LAST,
    P2_INFO = 31,       /* not a test: hands the plugin the guest's layout */
};

#define N_P2A      20       /* clock-freeze triggers */
#define K_P2B    1000       /* timer-window triggers (B3's K) */
#define LIVE_TICKS 50       /* liveness phase: periodic ticks required */
#define C2_PAGES  600       /* > CPU_SPEC_TLB_LOG_MAX */
#define P2B_DEADLINE 200000 /* LAPIC counts at divide 1: 200 us */

#define TIMER_VEC  0x40
#define SPUR_VEC   0xff

/* The fixed virtual layout this kernel builds (see setup_paging) */
#define RA          0x200000ul          /* region A: 4 KiB pages */
#define RO_DATA     (RA + 0x0000)       /* read-only data (T1_RO) */
#define RO_CODE     (RA + 0x1000)       /* read-only code: wp_victim copy */
#define HOLE        (RA + 0x2000)       /* not present */
#define STRADDLE    (RA + 0x3000)       /* nops into the next, absent page */
#define PROBE       (RA + 0x5000)       /* not present: C2's #PF probe */
#define RB          0x400000ul          /* region B: C2's 600 pages */
#define RC          0x800000ul          /* region C: page table in MMIO */
#define C4_VA       (RC + (0xc0 / 8) * 0x1000)  /* its PTE is e1000 ICR */

/* e1000 registers (offsets into BAR0) */
#define E1K_ICR 0xc0
#define E1K_ICS 0xc8
#define E1K_C1_BIT 0x20             /* C1: the bit a wrong-path ICS store sets */
#define E1K_C4_BIT 0x80             /* C4: the bit a PTW read of ICR would clear */

extern uint64_t wp_trigger(uint64_t test, uint64_t target, void *buf,
                           uint64_t len);
extern char wp_region_start[], wp_region_end[];
extern char wp_store[], wp_store_ro[], wp_clobber[], wp_ud[], wp_div[],
            wp_priv[], wp_int3[], wp_load_unmapped[], wp_syscall[],
            wp_loop[], wp_rep[], wp_spin[], wp_tsc[], wp_sti[], wp_mmio[],
            wp_tlb[], wp_gp[], wp_c3pf[], wp_c4[];
extern char victim_src[], victim_src_end[];
extern char isr_stubs[];
extern char probe_insn[], probe_resume[];
extern char pend_sti[], pend_after[];
extern uint64_t probe_read(uint64_t addr);

/* ------------------------------------------------------------------ asm */

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
    "wp_mxcsr_junk: .long 0x7f80\n"
    "wp_fcw_junk:   .short 0x0c7f\n"
    ".section .data\n"
    ".p2align 3\n"
    "wp_saved_rsp: .quad 0\n"
    "wp_mask: .long 0\n"

    ".text\n"
    /*
     * uint64_t wp_trigger(test=rdi, target=rsi, buf=rdx, len=rcx)
     * Byte-for-byte the linux-user victim's trigger.
     */
    ".globl wp_trigger\n"
    ".p2align 4\n"
    "wp_trigger:\n"
    "  push %rbx\n  push %rbp\n  push %r12\n  push %r13\n"
    "  push %r14\n  push %r15\n"
    "  push %rdi\n  push %rsi\n  push %rdx\n  push %rcx\n"
    "  sub $32, %rsp\n"
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

    /*
     * ---------------- wrong-path-only code ----------------
     * Everything between wp_region_start and wp_region_end is executed by
     * wrong paths alone.  An interrupt whose interrupted RIP lies in here
     * was delivered on a wrong path (B1).
     */
    ".p2align 12\n"
    ".globl wp_region_start\n"
    "wp_region_start:\n"
    ".globl wp_store\n"
    "wp_store:\n"                       /* rdx = buf (len 4096) */
    "  movabs $0x1122334455667788, %rax\n"
    "  mov %rax, (%rdx)\n"
    "  mov (%rdx), %rbx\n"
    "  mov %rbx, 8(%rdx)\n"
    "  movl $0xa5a5a5a5, 64(%rdx)\n"
    "  movb $0x5a, 4095(%rdx)\n"
    "  movdqu %xmm0, 128(%rdx)\n"
    "  jmp wp_clobber\n"

    ".p2align 6\n"
    ".globl wp_store_ro\n"
    "wp_store_ro:\n"                    /* rdx = RO_DATA; RO_CODE follows */
    "  movq $-1, (%rdx)\n"
    "  movq $-1, 56(%rdx)\n"
    "  movq $-1, 0x1000(%rdx)\n"
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
    "  cmp %rbx, %rcx\n"
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

    /*
     * CPL0 has no privileged-instruction fault, so the softmmu PRIV kind
     * is a #GP a kernel can take: wrmsr IA32_APIC_BASE with reserved bits.
     */
    ".p2align 4\n"
    ".globl wp_priv\n"
    ".globl wp_gp\n"
    "wp_priv:\n"
    "wp_gp:\n"
    "  mov $0x1b, %ecx\n  mov $-1, %eax\n  xor %edx, %edx\n"
    "  wrmsr\n"
    "  jmp wp_spin\n"

    ".p2align 4\n"
    ".globl wp_int3\n"
    "wp_int3:\n"
    "  int3\n"
    "  jmp wp_spin\n"

    ".p2align 4\n"
    ".globl wp_load_unmapped\n"
    "wp_load_unmapped:\n"
    "  mov $0x202010, %eax\n"           /* HOLE + 0x10: not present */
    "  mov (%rax), %rbx\n"
    "  mov %rbx, 24(%rdx)\n"
    "  jmp wp_spin\n"

    /* EFER.SCE is clear: syscall is #UD in this kernel */
    ".p2align 4\n"
    ".globl wp_syscall\n"
    "wp_syscall:\n"
    "  mov $1, %eax\n  mov $1, %edi\n"
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

    /* A3: an rdtsc pair split across two blocks, both stored into buf */
    ".p2align 4\n"
    ".globl wp_tsc\n"
    "wp_tsc:\n"
    "  mov %rdx, %rdi\n"
    "  rdtsc\n  shl $32, %rdx\n  or %rdx, %rax\n"
    "  mov %rax, (%rdi)\n"
    "  jmp 1f\n"
    "1:\n"
    "  rdtsc\n  shl $32, %rdx\n  or %rdx, %rax\n"
    "  mov %rax, 8(%rdi)\n"
    "  jmp wp_spin\n"

    /* B1: unmask a pending interrupt on the wrong path, then spin */
    ".p2align 4\n"
    ".globl wp_sti\n"
    "wp_sti:\n"
    "  sti\n"
    "  nop\n"
    "  nop\n"
    "2:\n"
    "  pause\n"
    "  jmp 2b\n"

    /*
     * C1: a serial THR write, a device store, a debug-exit write.  The
     * device store sits alone at the end of a page (wp_iopage below): an
     * MMIO access is only legal as the LAST instruction of a translation
     * block (can_do_io), and a block ends at a page boundary, so there it
     * can reach the device in the spec-OFF control too.
     */
    ".p2align 4\n"
    ".globl wp_mmio\n"
    "wp_mmio:\n"                        /* rdx = e1000 BAR0 */
    "  mov %rdx, %rdi\n"
    "  mov $0x3f8, %edx\n  mov $0x21, %al\n  out %al, (%dx)\n"
    "  jmp wp_mmio_st\n"

    /* C2: touch C2_PAGES fresh pages, then the not-present probe page */
    ".p2align 4\n"
    ".globl wp_tlb\n"
    "wp_tlb:\n"                         /* rdx = RB, rcx = pages */
    "  mov %rdx, %rdi\n"
    "3:\n"
    "  mov (%rdi), %rax\n"
    "  add $0x1000, %rdi\n"
    "  dec %rcx\n"
    "  jnz 3b\n"
    "  mov $0x205000, %edi\n"           /* PROBE */
    "  mov (%rdi), %rax\n"
    "  jmp wp_spin\n"

    /* C3: #PF on a non-present page, from CPL0: fetch from HOLE */
    ".p2align 4\n"
    ".globl wp_c3pf\n"
    "wp_c3pf:\n"
    "  mov $0x202000, %eax\n"
    "  jmp *%rax\n"

    /* C4: a load whose page-table walk reads its PTE from e1000 ICR (the
     * load is page-final for the same reason as C1's store) */
    ".p2align 4\n"
    ".globl wp_c4\n"
    "wp_c4:\n"
    "  mov $0x818000, %edi\n"           /* C4_VA */
    "  jmp wp_c4_ld\n"

    /* the page-final device accesses (see C1 above) */
    ".p2align 12\n"
    "wp_iopage:\n"
    "wp_mmio_tail:\n"
    "  mov $0xf4, %edx\n  mov $0x55, %al\n  out %al, (%dx)\n"
    "  jmp wp_spin\n"
    /* control C1NF only (F12 witness): the same device store, NOT the
     * last instruction of its block; the plugin finds it at the
     * page-final store's page + 0x800 */
    "  .org wp_iopage + 2048\n"
    "wp_mmio_mid:\n"
    "  nop\n"
    "  movl $0x20, 0xc8(%rdi)\n"
    "  nop\n"
    "  jmp wp_spin\n"
    "  .org wp_iopage + 4096 - 10\n"
    "wp_mmio_st:\n"
    "  movl $0x20, 0xc8(%rdi)\n"        /* ICS <- E1K_C1_BIT, 10 bytes */
    "  jmp wp_mmio_tail\n"              /* first bytes of the next page */
    "  .org wp_iopage + 8192 - 3\n"
    "wp_c4_ld:\n"
    "  mov (%rdi), %rax\n"              /* 3 bytes */
    "  jmp wp_spin\n"

    ".p2align 4\n"
    ".globl wp_region_end\n"
    "wp_region_end:\n"
    "  nop\n"

    /* correct-path code the wrong path tries to overwrite (copied to RO_CODE) */
    ".p2align 4\n"
    ".globl victim_src\n"
    ".globl victim_src_end\n"
    "victim_src:\n"
    "  mov $42, %eax\n"
    "  ret\n"
    "  .fill 10, 1, 0x90\n"
    "victim_src_end:\n"

    /* uint64_t probe_read(addr): 0 if the load succeeded, 1 if it faulted */
    ".p2align 4\n"
    ".globl probe_read\n"
    ".globl probe_insn\n"
    ".globl probe_resume\n"
    "probe_read:\n"
    "  xor %eax, %eax\n"
    "probe_insn:\n"
    "  mov (%rdi), %rcx\n"
    "probe_resume:\n"
    "  ret\n"

    /*
     * The ISR stubs: 256 x 16 bytes.  Vectors with a CPU error code push
     * only their number; the rest push a dummy error code first.
     */
    ".altmacro\n"
    ".macro isrstub n\n"
    "  .p2align 4\n"
    "  .if (\\n==8)||(\\n==10)||(\\n==11)||(\\n==12)||(\\n==13)||(\\n==14)||(\\n==17)||(\\n==21)||(\\n==29)||(\\n==30)\n"
    "    pushq $\\n\n"
    "  .else\n"
    "    pushq $0\n"
    "    pushq $\\n\n"
    "  .endif\n"
    "  jmp isr_common\n"
    ".endm\n"
    ".p2align 4\n"
    ".globl isr_stubs\n"
    "isr_stubs:\n"
    ".set vecno, 0\n"
    ".rept 256\n"
    "  isrstub %vecno\n"
    "  .set vecno, vecno+1\n"
    ".endr\n"
    ".noaltmacro\n"

    "isr_common:\n"
    "  push %rax\n  push %rbx\n  push %rcx\n  push %rdx\n"
    "  push %rsi\n  push %rdi\n  push %rbp\n"
    "  push %r8\n  push %r9\n  push %r10\n  push %r11\n"
    "  push %r12\n  push %r13\n  push %r14\n  push %r15\n"
    "  mov %rsp, %rdi\n"
    "  fxsave isr_fx(%rip)\n"
    "  call isr_dispatch\n"
    "  fxrstor isr_fx(%rip)\n"
    "  pop %r15\n  pop %r14\n  pop %r13\n  pop %r12\n"
    "  pop %r11\n  pop %r10\n  pop %r9\n  pop %r8\n"
    "  pop %rbp\n  pop %rdi\n  pop %rsi\n  pop %rdx\n"
    "  pop %rcx\n  pop %rbx\n  pop %rax\n"
    "  add $16, %rsp\n"
    "  iretq\n"

    /* P2B_PEND's correct-path unmask: the interrupt is taken after nop */
    ".globl pend_unmask\n"
    ".globl pend_sti\n"
    ".globl pend_after\n"
    "pend_unmask:\n"
    "pend_sti:\n"
    "  sti\n"
    "  nop\n"
    "pend_after:\n"
    "  cli\n"
    "  ret\n"

    ".section .bss\n"
    ".p2align 4\n"
    "isr_fx: .space 512\n"
    ".text\n"
);

extern void pend_unmask(void);

/* ---------------------------------------------------------- primitives */

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
static inline void outl(uint16_t p, uint32_t v)
{
    __asm__ volatile("outl %0, %1" : : "a"(v), "Nd"(p));
}
static inline uint32_t inl(uint16_t p)
{
    uint32_t v;
    __asm__ volatile("inl %1, %0" : "=a"(v) : "Nd"(p));
    return v;
}
static inline uint64_t rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
static inline uint64_t read_cr(int n)
{
    uint64_t v = 0;
    switch (n) {
    case 0: __asm__ volatile("mov %%cr0, %0" : "=r"(v)); break;
    case 2: __asm__ volatile("mov %%cr2, %0" : "=r"(v)); break;
    case 3: __asm__ volatile("mov %%cr3, %0" : "=r"(v)); break;
    case 4: __asm__ volatile("mov %%cr4, %0" : "=r"(v)); break;
    }
    return v;
}
static inline void write_cr0(uint64_t v)
{
    __asm__ volatile("mov %0, %%cr0" : : "r"(v) : "memory");
}
static inline void write_cr3(uint64_t v)
{
    __asm__ volatile("mov %0, %%cr3" : : "r"(v) : "memory");
}
static inline void write_cr4(uint64_t v)
{
    __asm__ volatile("mov %0, %%cr4" : : "r"(v) : "memory");
}
static inline void invlpg(uint64_t va)
{
    __asm__ volatile("invlpg (%0)" : : "r"(va) : "memory");
}
static inline void cli(void) { __asm__ volatile("cli" ::: "memory"); }
static inline void sti(void) { __asm__ volatile("sti" ::: "memory"); }
static inline void cpu_relax(void) { __asm__ volatile("pause" ::: "memory"); }

static inline uint32_t mmio_r32(uint64_t a)
{
    return *(volatile uint32_t *)a;
}
static inline void mmio_w32(uint64_t a, uint32_t v)
{
    *(volatile uint32_t *)a = v;
}

/* ------------------------------------------------------------- globals */

static uint8_t buf[4096] __attribute__((aligned(4096)));
static uint64_t p2abuf[2] __attribute__((aligned(16)));
static uint64_t pt_a[512] __attribute__((aligned(4096)));
static uint64_t pt_b[2][512] __attribute__((aligned(4096)));
static const uint64_t rodata_pat[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
static uint64_t *pd;                  /* the boot PD for 0..1 GiB */
static uint64_t e1k_bar;
static uint64_t tsc_per_ms;
static int failures;

/* interrupt bookkeeping (written by the ISR) */
static volatile uint64_t vec_count[256];
static volatile uint64_t irq_total;       /* hardware interrupts taken */
static volatile uint64_t wp_rip_irqs;     /* interrupted RIP in wp region */
#define LOG_N 64
static volatile struct { uint64_t vec, rip, tsc; } irq_log[LOG_N];
static volatile uint64_t irq_log_n;
static volatile bool pf_expect;
static volatile uint64_t pf_count;
static volatile bool isr_trigger_armed;   /* P2B_ISR: trigger from the ISR */
static volatile uint64_t isr_trigger_mask = ~0ull;
static volatile uint64_t timer_armed;     /* one-shots programmed (B4) */

struct frame {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8, rbp, rdi, rsi, rdx, rcx,
             rbx, rax, vec, err, rip, cs, rflags, rsp, ss;
};

/* ------------------------------------------------------------- output */

static void dbg_exit(uint8_t code)
{
    outb(0xf4, code);          /* isa-debug-exit: QEMU exits (code<<1)|1 */
    for (;;) {
        __asm__ volatile("cli; hlt");
    }
}

static void serial_init(void)
{
    outb(0x3f9, 0x00);
    outb(0x3fb, 0x80);
    outb(0x3f8, 0x01);
    outb(0x3f9, 0x00);
    outb(0x3fb, 0x03);
    outb(0x3fa, 0xc7);
    outb(0x3fc, 0x03);
}

static void serial_puts(const char *s)
{
    for (; *s; s++) {
        while (!(inb(0x3fd) & 0x20)) {
            cpu_relax();
        }
        outb(0x3f8, (uint8_t)*s);
    }
}

/* ----------------------------------------------------------------- ISR */

#define LAPIC 0xfee00000ul

static void lapic_eoi(void)
{
    mmio_w32(LAPIC + 0xb0, 0);
}

static bool in_wp_region(uint64_t rip)
{
    return rip >= (uint64_t)wp_region_start && rip < (uint64_t)wp_region_end;
}

__attribute__((used))
void isr_dispatch(struct frame *f)
{
    uint64_t v = f->vec & 0xff;
    vec_count[v]++;
    if (v == 14 && pf_expect && f->rip == (uint64_t)probe_insn) {
        /* C2's probe: count the #PF, report it, skip the load */
        pf_count++;
        f->rax = 1;
        f->rip = (uint64_t)probe_resume;
        return;
    }
    if (v < 32) {
        /* an exception nobody asked for: a leaked wrong-path fault */
        ml_printf("[wp-victim-sys] FAIL T3: guest observed exception "
                  "vector 0x%x err 0x%lx at rip 0x%lx cr2 0x%lx\n",
                  (unsigned)v, f->err, f->rip, read_cr(2));
        dbg_exit(99);
    }
    if (v == SPUR_VEC) {
        return;                /* spurious: no EOI */
    }
    irq_total++;
    uint64_t n = irq_log_n;
    irq_log[n % LOG_N].vec = v;
    irq_log[n % LOG_N].rip = f->rip;
    irq_log[n % LOG_N].tsc = rdtsc();
    irq_log_n = n + 1;
    if (in_wp_region(f->rip)) {
        wp_rip_irqs++;
        ml_printf("[wp-victim-sys] FAIL B1: interrupt vector 0x%x delivered "
                  "on wrong-path-only code at rip 0x%lx\n", (unsigned)v,
                  f->rip);
        dbg_exit(97);
    }
    if (v == TIMER_VEC && isr_trigger_armed) {
        isr_trigger_armed = false;
        isr_trigger_mask = wp_trigger(P2B_ISR, (uint64_t)wp_spin, buf,
                                      sizeof(buf));
    }
    lapic_eoi();
}

/* print the ISR's log since @from, then forget it */
static void flush_irq_log(uint64_t from, const char *tag)
{
    uint64_t n = irq_log_n;
    for (uint64_t i = from; i < n; i++) {
        ml_printf("[irq] %s v=0x%lx rip=0x%lx tsc=0x%lx\n", tag,
                  irq_log[i % LOG_N].vec, irq_log[i % LOG_N].rip,
                  irq_log[i % LOG_N].tsc);
    }
}

/* ----------------------------------------------------------- IDT etc. */

static uint64_t idt[512] __attribute__((aligned(16)));
static struct __attribute__((packed)) { uint16_t lim; uint64_t base; }
    idtr, idtr_null;

static void setup_idt(void)
{
    for (int v = 0; v < 256; v++) {
        uint64_t h = (uint64_t)isr_stubs + 16 * v;
        uint64_t lo = (h & 0xffff) | (0x8ull << 16) | (0x8eull << 40) |
                      ((h >> 16 & 0xffff) << 48);
        idt[2 * v] = lo;
        idt[2 * v + 1] = h >> 32;
    }
    idtr.lim = sizeof(idt) - 1;
    idtr.base = (uint64_t)idt;
    idtr_null.lim = 0;
    idtr_null.base = 0;
    __asm__ volatile("lidt %0" : : "m"(idtr));
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

static void mask_pic(void)
{
    outb(0x21, 0xff);
    outb(0xa1, 0xff);
}

/* ------------------------------------------------------------- paging */

#define PFN(x) ((x) & 0x000ffffffffff000ull)

static void setup_paging(void)
{
    uint64_t *pml4 = (uint64_t *)PFN(read_cr(3));
    uint64_t *pdp = (uint64_t *)PFN(pml4[0]);
    pd = (uint64_t *)PFN(pdp[0]);

    /* region A: 4 KiB pages, all present+writable to fill them first */
    for (int i = 0; i < 512; i++) {
        pt_a[i] = 0;
    }
    pt_a[0] = RO_DATA | 3;
    pt_a[1] = RO_CODE | 3;
    pt_a[3] = STRADDLE | 3;
    pd[1] = (uint64_t)pt_a | 3;

    /* region B: C2's pages */
    for (int i = 0; i < 1024; i++) {
        pt_b[i / 512][i % 512] = i < C2_PAGES ? (RB + i * 0x1000ull) | 3 : 0;
    }
    pd[2] = (uint64_t)pt_b[0] | 3;
    pd[3] = (uint64_t)pt_b[1] | 3;
    write_cr3(read_cr(3));

    /* fill: read-only data, a victim function copy, the straddle page */
    uint64_t *ro = (uint64_t *)RO_DATA;
    for (int i = 0; i < 512; i++) {
        ro[i] = i < 8 ? rodata_pat[i] : 0;
    }
    uint8_t *code = (uint8_t *)RO_CODE;
    for (int i = 0; i < 4096; i++) {
        code[i] = 0xcc;
    }
    for (int i = 0; victim_src + i < victim_src_end; i++) {
        code[i] = (uint8_t)victim_src[i];
    }
    uint8_t *pg = (uint8_t *)STRADDLE;
    for (int i = 0; i < 4096; i++) {
        pg[i] = 0x90;
    }
    pg[4096 - 3] = 0x48;       /* movabs $imm64, %rax straddling the edge */
    pg[4096 - 2] = 0xb8;

    /* now make RO_DATA and RO_CODE read-only, and turn on CR0.WP */
    pt_a[0] = RO_DATA | 1;
    pt_a[1] = RO_CODE | 1;
    invlpg(RO_DATA);
    invlpg(RO_CODE);
    write_cr0(read_cr(0) | (1ull << 16));
}

/* --------------------------------------------------------------- e1000 */

static uint32_t pci_rd(int dev, int off)
{
    outl(0xcf8, 0x80000000u | (dev << 11) | off);
    return inl(0xcfc);
}
static void pci_wr(int dev, int off, uint32_t v)
{
    outl(0xcf8, 0x80000000u | (dev << 11) | off);
    outl(0xcfc, v);
}

static void setup_e1000(void)
{
    for (int dev = 0; dev < 32; dev++) {
        if (pci_rd(dev, 0) == 0x100e8086u) {
            uint32_t bar = pci_rd(dev, 0x10) & ~0xfu;
            if (bar == 0) {
                bar = 0xfeb80000u;
                pci_wr(dev, 0x10, bar);
            }
            pci_wr(dev, 4, (pci_rd(dev, 4) & 0xffff) | 0x6);
            e1k_bar = bar;
            break;
        }
    }
    if (!e1k_bar) {
        ml_printf("[wp-victim-sys] FAIL setup: no e1000 (subject absent for "
                  "C1/C4)\n");
        failures++;
        return;
    }
    mmio_w32(e1k_bar + 0xd8, 0xffffffffu);  /* IMC: no e1000 interrupts */
    (void)mmio_r32(e1k_bar + E1K_ICR);      /* clear whatever is pending */
    /* region C: a "page table" whose PTEs are e1000 registers */
    pd[4] = (uint64_t)e1k_bar | 3;
    write_cr3(read_cr(3));
}

/* --------------------------------------------------------------- LAPIC */

static void lapic_w(uint32_t off, uint32_t v)
{
    mmio_w32(LAPIC + off, v);
}
static uint32_t lapic_r(uint32_t off)
{
    return mmio_r32(LAPIC + off);
}

static void lapic_init(void)
{
    lapic_w(0xf0, 0x100 | SPUR_VEC);      /* SVR: enable */
    lapic_w(0x80, 0);                     /* TPR */
    lapic_w(0x350, 1u << 16);             /* LINT0 masked */
    lapic_w(0x360, 1u << 16);             /* LINT1 masked */
    lapic_w(0x3e0, 0xb);                  /* divide by 1: 1 count = 1 ns */
    lapic_w(0x320, (1u << 16) | TIMER_VEC);
    lapic_w(0x380, 0);
}

static void timer_oneshot(uint32_t count)
{
    lapic_w(0x320, TIMER_VEC);
    lapic_w(0x380, count);
    timer_armed++;
}

static void timer_periodic(uint32_t count)
{
    lapic_w(0x320, (1u << 17) | TIMER_VEC);
    lapic_w(0x380, count);
}

static void timer_stop(void)
{
    lapic_w(0x320, (1u << 16) | TIMER_VEC);
    lapic_w(0x380, 0);
}

static bool timer_irr_pending(void)
{
    uint32_t reg = 0x200 + (TIMER_VEC / 32) * 0x10;
    return lapic_r(reg) & (1u << (TIMER_VEC % 32));
}

/* TSC ticks per LAPIC millisecond (1e6 counts at divide 1) */
static void calibrate_tsc(void)
{
    lapic_w(0x320, (1u << 16) | TIMER_VEC);   /* masked one-shot */
    uint64_t t0 = rdtsc();
    lapic_w(0x380, 1000000);
    while (lapic_r(0x390) != 0) {
        cpu_relax();
    }
    tsc_per_ms = rdtsc() - t0;
    lapic_w(0x380, 0);
}

/* ------------------------------------------------------------- phase 1 */

static void fill_buf(void)
{
    for (int i = 0; i < (int)sizeof(buf); i++) {
        buf[i] = (uint8_t)(i * 7 + 3);
    }
}

static uint64_t fnv(const void *p, uint64_t n)
{
    const uint8_t *b = p;
    uint64_t h = 0xcbf29ce484222325ull;
    for (uint64_t i = 0; i < n; i++) {
        h = (h ^ b[i]) * 0x100000001b3ull;
    }
    return h;
}

static void check_world(int test)
{
    for (int i = 0; i < (int)sizeof(buf); i++) {
        if (buf[i] != (uint8_t)(i * 7 + 3)) {
            ml_printf("[wp-victim-sys] FAIL test %d: buf[%d]=0x%x corrupted\n",
                      test, i, buf[i]);
            failures++;
            break;
        }
    }
    const uint64_t *ro = (const uint64_t *)RO_DATA;
    for (int i = 0; i < 8; i++) {
        if (ro[i] != rodata_pat[i]) {
            ml_printf("[wp-victim-sys] FAIL test %d: read-only data "
                      "corrupted\n", test);
            failures++;
            break;
        }
    }
    const uint8_t *code = (const uint8_t *)RO_CODE;
    for (int i = 0; victim_src + i < victim_src_end; i++) {
        if (code[i] != (uint8_t)victim_src[i]) {
            ml_printf("[wp-victim-sys] FAIL test %d: code page corrupted\n",
                      test);
            failures++;
            break;
        }
    }
    if (((int (*)(void))RO_CODE)() != 42) {
        ml_printf("[wp-victim-sys] FAIL test %d: victim code returned the "
                  "wrong value\n", test);
        failures++;
    }
}

static uint64_t run(int test, void *target, void *b, uint64_t len)
{
    uint64_t irq0 = irq_total;
    uint64_t mask = wp_trigger(test, (uint64_t)target, b, len);
    uint64_t irq1 = irq_total;
    check_world(test);
    ml_printf("[wp-victim-sys] test %d regmask=0x%lx bufsum=%lx\n", test, mask,
              fnv(buf, sizeof(buf)));
    if (mask) {
        ml_printf("[wp-victim-sys] FAIL test %d: registers changed across the "
                  "excursion (mask 0x%lx)\n", test, mask);
        failures++;
    }
    if (irq1 != irq0) {
        ml_printf("[wp-victim-sys] FAIL B1 test %d: %lu interrupts taken "
                  "inside the trigger\n", test, irq1 - irq0);
        failures++;
    }
    return mask;
}

/* ------------------------------------------------------------- phase 2 */

static void p2a_clock(void)
{
    for (int i = 0; i < N_P2A; i++) {
        p2abuf[0] = p2abuf[1] = 0;
        uint64_t t0 = rdtsc();
        uint64_t mask = wp_trigger(P2A_CLOCK, (uint64_t)wp_tsc, p2abuf,
                                   sizeof(p2abuf));
        uint64_t t1 = rdtsc();
        /* host-time dependent: compared numerically by the runner */
        ml_printf("[p2a] i=%d trigger_tsc_delta=%lu\n", i, t1 - t0);
        if (mask) {
            ml_printf("[wp-victim-sys] FAIL P2A: registers changed (mask "
                      "0x%lx)\n", mask);
            failures++;
        }
        if (p2abuf[0] || p2abuf[1]) {
            ml_printf("[wp-victim-sys] FAIL P2A: wrong-path rdtsc stores "
                      "reached memory\n");
            failures++;
        }
    }
}

/* P2-A liveness: the guest clock keeps running after the excursions */
static void liveness(void)
{
    uint64_t c0 = vec_count[TIMER_VEC];
    timer_periodic(1000000);                 /* 1 ms */
    sti();
    while (vec_count[TIMER_VEC] - c0 < LIVE_TICKS) {
        cpu_relax();
    }
    cli();
    timer_stop();
    irq_log_n = 0;
    ml_printf("[wp-victim-sys] liveness ticks=%d\n", LIVE_TICKS);
}

/*
 * P2-B: a one-shot whose deadline lies after the trigger (P2B_DEADLINE
 * counts = ns; under -icount shift=0, instructions), armed immediately
 * before it.  The plugin's busy-wait inside the excursion (bdelay_us,
 * default 1 ms) is longer than the deadline, so a guest clock that ran
 * during the excursion would expire it on the wrong path's watch.  Interrupts stay enabled: the trigger must not take it (B1),
 * the correct path takes it exactly once at the position a run without
 * excursions takes it (B2, byte identity under icount), and K of them are
 * neither lost nor duplicated (B3/B4).
 */
static void p2b_timer(void)
{
    uint64_t armed0 = timer_armed, fired0 = vec_count[TIMER_VEC];
    for (int k = 0; k < K_P2B; k++) {
        uint64_t n0 = irq_log_n;
        uint64_t c0 = vec_count[TIMER_VEC];
        sti();
        timer_oneshot(P2B_DEADLINE);
        uint64_t mask = wp_trigger(P2B_TIMER, (uint64_t)wp_spin, buf,
                                   sizeof(buf));
        uint64_t c1 = vec_count[TIMER_VEC];
        while (vec_count[TIMER_VEC] == c0) {
            cpu_relax();
        }
        cli();
        if (mask || c1 != c0) {
            ml_printf("[wp-victim-sys] FAIL P2B k=%d: mask=0x%lx, %lu "
                      "interrupts inside the trigger\n", k, mask, c1 - c0);
            failures++;
        }
        if (k < 8 || k % 100 == 0) {
            flush_irq_log(n0, "p2b");
        }
        irq_log_n = 0;
    }
    uint64_t armed = timer_armed - armed0;
    uint64_t fired = vec_count[TIMER_VEC] - fired0;
    ml_printf("[wp-victim-sys] P2B armed=%lu fired=%lu\n", armed, fired);
    if (armed != K_P2B || fired != armed) {
        ml_printf("[wp-victim-sys] FAIL B4: %lu timer interrupts for %lu "
                  "programmed\n", fired, armed);
        failures++;
    }
}

/*
 * P2-B, the pending form: with interrupts masked, let the one-shot expire
 * so its vector sits pending in the LAPIC, then trigger a wrong path that
 * executes sti.  The wrong path must not take it; the correct path takes
 * it on its own sti, after the one-instruction shadow, at pend_after.
 */
static void p2b_pend(void)
{
    cli();
    timer_oneshot(1000);
    while (!timer_irr_pending()) {
        cpu_relax();
    }
    uint64_t c0 = vec_count[TIMER_VEC];
    uint64_t n0 = irq_log_n;
    uint64_t mask = wp_trigger(P2B_PEND, (uint64_t)wp_sti, buf, sizeof(buf));
    uint64_t c1 = vec_count[TIMER_VEC];
    bool still = timer_irr_pending();
    pend_unmask();
    uint64_t c2 = vec_count[TIMER_VEC];
    ml_printf("[wp-victim-sys] P2B_PEND subject pending=1 after=%d "
              "in_trigger=%lu taken=%lu rip_ok=%d\n", still, c1 - c0,
              c2 - c1, irq_log_n > n0 &&
              irq_log[n0 % LOG_N].rip == (uint64_t)pend_after);
    if (mask || c1 != c0 || !still || c2 - c1 != 1 ||
        irq_log[n0 % LOG_N].rip != (uint64_t)pend_after) {
        ml_printf("[wp-victim-sys] FAIL B1/B2 pend: mask=0x%lx in_trigger=%lu "
                  "still_pending=%d taken=%lu rip=0x%lx want 0x%lx\n", mask,
                  c1 - c0, still, c2 - c1, irq_log[n0 % LOG_N].rip,
                  (uint64_t)pend_after);
        failures++;
    }
    irq_log_n = 0;
}

/* P2-B: a trigger from inside the timer ISR (the async window is open) */
static void p2b_isr(void)
{
    uint64_t c0 = vec_count[TIMER_VEC];
    isr_trigger_armed = true;
    sti();
    timer_oneshot(2000);
    while (vec_count[TIMER_VEC] == c0) {
        cpu_relax();
    }
    cli();
    irq_log_n = 0;
    ml_printf("[wp-victim-sys] P2B_ISR regmask=0x%lx\n", isr_trigger_mask);
    if (isr_trigger_mask) {
        ml_printf("[wp-victim-sys] FAIL P2B_ISR: registers changed (mask "
                  "0x%lx)\n", isr_trigger_mask);
        failures++;
    }
}

/* C1: the wrong path writes a device register, COM1's THR, debug-exit */
static void c1_mmio(void)
{
    if (!e1k_bar) {
        return;
    }
    (void)mmio_r32(e1k_bar + E1K_ICR);
    run(C1_MMIO, wp_mmio, (void *)e1k_bar, 0);
    uint32_t icr = mmio_r32(e1k_bar + E1K_ICR);
    ml_printf("[wp-victim-sys] C1 icr_bit=%d\n", !!(icr & E1K_C1_BIT));
    if (icr & E1K_C1_BIT) {
        ml_printf("[wp-victim-sys] FAIL C1: a wrong-path store reached the "
                  "e1000 (ICR 0x%x)\n", icr);
        failures++;
    }
    /* the detector's own witness: a correct-path store of the same bit
     * must show up in the same read */
    mmio_w32(e1k_bar + E1K_ICS, E1K_C1_BIT);
    icr = mmio_r32(e1k_bar + E1K_ICR);
    ml_printf("[wp-victim-sys] C1 detector witness: CP store -> icr_bit=%d\n",
              !!(icr & E1K_C1_BIT));
    if (!(icr & E1K_C1_BIT)) {
        ml_printf("[wp-victim-sys] FAIL C1: the ICR detector cannot see a "
                  "device store (subject absent)\n");
        failures++;
    }
}

/*
 * C2: the wrong path loads from 600 fresh pages and from a not-present one.
 * Afterwards the correct path unmaps the 600 WITHOUT invlpg -- it never
 * touched them, so no translation of its own can be cached -- and reads
 * each: all 600 must fault, exactly as with no wrong path, whatever the
 * wrong path's walks installed.  The not-present probe must fault too.
 */
static void c2_tlb(void)
{
    run(C2_TLB, wp_tlb, (void *)RB, C2_PAGES);
    for (int i = 0; i < C2_PAGES; i++) {
        pt_b[i / 512][i % 512] = 0;
    }
    pf_count = 0;
    pf_expect = true;
    uint64_t faulted = 0;
    for (int i = 0; i < C2_PAGES; i++) {
        faulted += probe_read(RB + i * 0x1000ull);
    }
    uint64_t probe = probe_read(PROBE);
    pf_expect = false;
    ml_printf("[wp-victim-sys] C2 faulted=%lu/%d probe=%lu pf=%lu\n", faulted,
              C2_PAGES, probe, pf_count);
    if (faulted != C2_PAGES || probe != 1 || pf_count != C2_PAGES + 1) {
        ml_printf("[wp-victim-sys] FAIL C2: the correct path's page faults "
                  "changed after the wrong path (%lu of %d, probe %lu)\n",
                  faulted, C2_PAGES, probe);
        failures++;
    }
    for (int i = 0; i < C2_PAGES; i++) {
        pt_b[i / 512][i % 512] = (RB + i * 0x1000ull) | 3;
        invlpg(RB + i * 0x1000ull);
    }
}

/* C3: CPL0 faults on the wrong path inside an IDT-less window */
static void c3_kfault(void)
{
    uint64_t df0 = vec_count[8];
    cli();
    __asm__ volatile("lidt %0" : : "m"(idtr_null));
    uint64_t m1 = wp_trigger(C3_GP, (uint64_t)wp_gp, buf, sizeof(buf));
    uint64_t m2 = wp_trigger(C3_PF, (uint64_t)wp_c3pf, buf, sizeof(buf));
    uint64_t m3 = wp_trigger(C3_UD, (uint64_t)wp_ud, buf, sizeof(buf));
    __asm__ volatile("lidt %0" : : "m"(idtr));
    ml_printf("[wp-victim-sys] C3 survived regmask=0x%lx/0x%lx/0x%lx df=%lu\n",
              m1, m2, m3, vec_count[8] - df0);
    if (m1 || m2 || m3 || vec_count[8] != df0) {
        ml_printf("[wp-victim-sys] FAIL C3\n");
        failures++;
    }
}

/* C4: a page-table walk whose PTE lives in MMIO must not read the device */
static void c4_ptw(void)
{
    if (!e1k_bar) {
        return;
    }
    (void)mmio_r32(e1k_bar + E1K_ICR);
    mmio_w32(e1k_bar + E1K_ICS, E1K_C4_BIT);     /* ICR <- bit */
    run(C4_PTW, wp_c4, 0, 0);    /* no buffer: a plugin read of C4_VA would walk the MMIO PTE itself */
    uint32_t icr = mmio_r32(e1k_bar + E1K_ICR);   /* read-to-clear */
    ml_printf("[wp-victim-sys] C4 icr_bit=%d\n", !!(icr & E1K_C4_BIT));
    if (!(icr & E1K_C4_BIT)) {
        ml_printf("[wp-victim-sys] FAIL C4: the device register was read "
                  "(cleared) by a wrong-path page walk\n");
        failures++;
    }
    /* the detector's own witness: a correct-path load through the same
     * MMIO PTE walks it, the device read clears the bit, the PTE (0x80,
     * not present) faults */
    mmio_w32(e1k_bar + E1K_ICS, E1K_C4_BIT);
    pf_count = 0;
    pf_expect = true;
    uint64_t f = probe_read(C4_VA);
    pf_expect = false;
    icr = mmio_r32(e1k_bar + E1K_ICR);
    ml_printf("[wp-victim-sys] C4 detector witness: CP walk -> faulted=%lu "
              "icr_bit=%d\n", f, !!(icr & E1K_C4_BIT));
    if (f != 1 || (icr & E1K_C4_BIT)) {
        ml_printf("[wp-victim-sys] FAIL C4: the ICR detector cannot see a "
                  "page-walk device read (subject absent)\n");
        failures++;
    }
}

int main(void)
{
    setup_sse();
    mask_pic();
    setup_idt();
    setup_paging();
    serial_init();
    serial_puts("SERIAL-CP-BEGIN\n");
    setup_e1000();
    lapic_init();
    calibrate_tsc();
    /* host-time dependent, compared numerically by the runner */
    ml_printf("[p2a] tsc_per_ms=%lu\n", tsc_per_ms);

    wp_trigger(P2_INFO, (uint64_t)wp_region_start, wp_region_end, tsc_per_ms);

    fill_buf();
    run(T1_STORE, wp_store, buf, sizeof(buf));
    run(T1_RO, wp_store_ro, (void *)RO_DATA, 64);
    run(T2_REGS, wp_clobber, buf, sizeof(buf));
    run(T3_FETCH_UNMAPPED, (void *)HOLE, buf, sizeof(buf));
    run(T3_STRADDLE, (void *)(STRADDLE + 4096 - 3 - 16), buf, sizeof(buf));
    run(T3_UD, wp_ud, buf, sizeof(buf));
    run(T3_DIV0, wp_div, buf, sizeof(buf));
    run(T3_PRIV, wp_priv, buf, sizeof(buf));
    run(T3_INT3, wp_int3, buf, sizeof(buf));
    run(T3_LOAD_UNMAPPED, wp_load_unmapped, buf, sizeof(buf));
    run(T3_SYSCALL, wp_syscall, buf, sizeof(buf));
    run(T4_LOOP, wp_loop, buf, sizeof(buf));
    run(T4_REP, wp_rep, buf, sizeof(buf));
    run(T5_REPEAT, wp_store, buf, sizeof(buf));

    p2a_clock();
    liveness();
    p2b_timer();
    p2b_pend();
    p2b_isr();
    c1_mmio();
    c2_tlb();
    c3_kfault();
    c4_ptw();

    ml_printf("[wp-victim-sys] victim=%d\n", ((int (*)(void))RO_CODE)());
    uint64_t exc = 0;
    for (int v = 0; v < 32; v++) {
        exc += vec_count[v];
    }
    ml_printf("[wp-victim-sys] vectors: timer=%lu exceptions=%lu (pf %lu) "
              "wp_rip=%lu\n", vec_count[TIMER_VEC], exc, vec_count[14],
              wp_rip_irqs);
    serial_puts("SERIAL-CP-END\n");
    ml_printf("[wp-victim-sys] %s (%d failures)\n",
              failures ? "FAILED" : "done", failures);
    return failures ? 1 : 0;
}
