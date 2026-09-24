/*
 * Instruction-count trigger (tdata1 type 3) privilege gating.
 *
 * The trigger has one enable bit per privilege level -- U, S, M and, for a
 * virtualised guest, VU and VS.  A bit that is set means "count instructions
 * retired at this privilege level"; a bit that is clear means "do not".  This
 * test arms trigger 0 with exactly one of those bits at a time, executes a
 * loop of a known length at each privilege level in turn, and reads the
 * remaining count back out of tdata1.  The count must fall by the length of
 * the loop when the level is enabled and must not move when it is not.
 *
 * A differential pass repeats the measurement with two loop lengths and
 * asserts the difference, which cancels the fixed cost of arming, switching
 * privilege and reading back, so the assertion is about the loop's
 * instructions and nothing else.
 *
 * Exit code 0 on success.  1..N names the failing cell in `cells' below,
 * 101..105 the failing differential cell in `diffcells', 90 an unexpected
 * trap.
 *
 * Author: Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define ITRIG_U         (1 << 6)
#define ITRIG_S         (1 << 7)
#define ITRIG_M         (1 << 9)
#define ITRIG_VU        (1 << 25)
#define ITRIG_VS        (1 << 26)

#define AT_M            0
#define AT_S            1
#define AT_U            2
#define AT_VS           3
#define AT_VU           4
#define AT_END          (-1)

#define ARM_COUNT       12000
#define ITER_BIG        2000
#define ITER_SMALL      1000
/* the loop is `addi; bnez', so two instructions per iteration */
#define EXPECT_BIG      (2 * ITER_BIG)
#define EXPECT_DIFF     (2 * (ITER_BIG - ITER_SMALL))
/*
 * Slack for the fixed cost either side of the loop: the privilege switch, the
 * ecall back, the trap handler and the tdata1 readback.  Two orders of
 * magnitude below the loop length, so a counted level and an uncounted one
 * cannot be confused.
 */
#define TOL             512
#define TOL_DIFF        64

#define CSR_TSELECT     0x7a0
#define CSR_TDATA1      0x7a1

#define MSTATUS_MPP     0x1800
#define MSTATUS_MPV_BIT 39

        .option norvc
        .text
        .global _start
_start:
        la      t0, trap
        csrw    mtvec, t0
        la      sp, stack_top

        /*
         * Nothing may steal a privilege transition from under the
         * measurement, so no interrupt is enabled and no trap is delegated:
         * every ecall lands in M mode, in this file's handler.
         */
        csrw    mie, zero
        csrw    medeleg, zero
        csrw    mideleg, zero
        csrw    hedeleg, zero
        csrw    hideleg, zero
        csrw    satp, zero
        csrw    hgatp, zero
        csrw    vsatp, zero

        /* S, VS, U and VU need a PMP entry or every fetch faults */
        li      t0, -1
        csrw    pmpaddr0, t0
        li      t0, 0x1f                /* NAPOT, R|W|X */
        csrw    pmpcfg0, t0

        csrw    CSR_TSELECT, zero

        /* ---------------- per-level gating ---------------- */
        la      s1, cells
        li      s2, 0
cell_loop:
        lw      s5, 0(s1)               /* enable bit */
        lw      s6, 4(s1)               /* level to execute at */
        lw      s7, 8(s1)               /* 1 if that level must be counted */
        bltz    s6, diff_start
        addi    s1, s1, 12
        addi    s2, s2, 1

        mv      a0, s5
        mv      a1, s6
        li      a2, ITER_BIG
        call    measure
        mv      s8, a0

        mv      a0, s2
        call    puthex
        mv      a0, s8
        call    puthex
        call    putnl

#ifdef ITRIG_SURVEY
        j       cell_loop               /* report every cell, assert none */
#endif
        beqz    s7, cell_uncounted
        li      a1, EXPECT_BIG - TOL
        li      a2, EXPECT_BIG + TOL
        mv      a0, s8
        call    check_range
        j       cell_loop
cell_uncounted:
        li      a1, -TOL
        li      a2, TOL
        mv      a0, s8
        call    check_range
        j       cell_loop

        /* ---------------- how many instructions ---------------- */
diff_start:
        la      s1, diffcells
        li      s2, 100
diff_loop:
        lw      s5, 0(s1)
        lw      s6, 4(s1)
        bltz    s6, all_done
        addi    s1, s1, 8
        addi    s2, s2, 1

        mv      a0, s5
        mv      a1, s6
        li      a2, ITER_BIG
        call    measure
        mv      s8, a0

        mv      a0, s5
        mv      a1, s6
        li      a2, ITER_SMALL
        call    measure
        sub     s8, s8, a0

        mv      a0, s2
        call    puthex
        mv      a0, s8
        call    puthex
        call    putnl

#ifdef ITRIG_SURVEY
        j       diff_loop
#endif
        li      a1, EXPECT_DIFF - TOL_DIFF
        li      a2, EXPECT_DIFF + TOL_DIFF
        mv      a0, s8
        call    check_range
        j       diff_loop

all_done:
        li      a0, 0
        j       _exit

/*
 * a0 = enable bit, a1 = level, a2 = loop iterations.
 * Returns in a0 the fall in tdata1's count field across the loop.
 */
measure:
        addi    sp, sp, -32
        sd      ra, 0(sp)
        sd      s10, 8(sp)
        sd      s11, 16(sp)
        sd      a2, 24(sp)
        mv      s10, a1
        li      a1, ARM_COUNT
        call    arm_trigger
        call    read_count
        mv      s11, a0
        ld      a0, 24(sp)
        mv      a1, s10
        call    excursion
        call    read_count
        sub     a0, s11, a0
        ld      ra, 0(sp)
        ld      s10, 8(sp)
        ld      s11, 16(sp)
        addi    sp, sp, 32
        ret

/* a0 = enable bit, a1 = count */
arm_trigger:
        li      t0, 3
        slli    t0, t0, 60              /* tdata1.type = 3, instruction count */
        csrw    CSR_TDATA1, t0          /* disarm: no level, no count */
        slli    t1, a1, 10
        or      t0, t0, t1
        or      t0, t0, a0
        csrw    CSR_TDATA1, t0
        ret

read_count:
        csrr    a0, CSR_TDATA1
        srli    a0, a0, 10
        li      t0, 0x3fff
        and     a0, a0, t0
        ret

/* a0 = loop iterations, a1 = level */
excursion:
        li      t0, AT_M
        beq     a1, t0, exc_body_m
        li      t0, AT_S
        beq     a1, t0, exc_s
        li      t0, AT_U
        beq     a1, t0, exc_u
        li      t0, AT_VS
        beq     a1, t0, exc_vs
        j       exc_vu

exc_body_m:
1:      addi    a0, a0, -1
        bnez    a0, 1b
        ret

        /*
         * ra has to survive the excursion -- the handler returns to exc_back,
         * which returns to measure -- so none of these may use `call'.
         */
exc_s:
        li      t0, MSTATUS_MPP
        csrc    mstatus, t0
        li      t0, (1 << 11)
        csrs    mstatus, t0
        li      t0, 1
        slli    t0, t0, MSTATUS_MPV_BIT
        csrc    mstatus, t0
        j       exc_enter
exc_u:
        li      t0, MSTATUS_MPP
        csrc    mstatus, t0
        li      t0, 1
        slli    t0, t0, MSTATUS_MPV_BIT
        csrc    mstatus, t0
        j       exc_enter
exc_vs:
        li      t0, MSTATUS_MPP
        csrc    mstatus, t0
        li      t0, (1 << 11)
        csrs    mstatus, t0
        li      t0, 1
        slli    t0, t0, MSTATUS_MPV_BIT
        csrs    mstatus, t0
        j       exc_enter
exc_vu:
        li      t0, MSTATUS_MPP
        csrc    mstatus, t0
        li      t0, 1
        slli    t0, t0, MSTATUS_MPV_BIT
        csrs    mstatus, t0
        j       exc_enter

exc_enter:
        la      s0, exc_back
        la      t0, exc_body
        csrw    mepc, t0
        mret
exc_back:
        ret

        /* the measured stretch, executed at whichever level was entered */
exc_body:
1:      addi    a0, a0, -1
        bnez    a0, 1b
        ecall

trap:
        csrr    t0, mcause
        li      t1, 8                   /* ecall from U, or from VU */
        beq     t0, t1, 1f
        li      t1, 9                   /* ecall from S */
        beq     t0, t1, 1f
        li      t1, 10                  /* ecall from VS */
        beq     t0, t1, 1f
        li      a0, 90
        j       _exit
1:      jr      s0

/* a0 = value, a1 = low bound, a2 = high bound; exits with s2 if outside */
check_range:
        blt     a0, a1, 1f
        bgt     a0, a2, 1f
        ret
1:      mv      a0, s2
        j       _exit

/* a0 = value, printed as four hex digits */
puthex:
        addi    sp, sp, -32
        sd      ra, 0(sp)
        sd      s0, 8(sp)
        sd      s1, 16(sp)
        mv      s0, a0
        li      s1, 12
1:      srl     a0, s0, s1
        andi    a0, a0, 0xf
        li      t0, 10
        blt     a0, t0, 2f
        addi    a0, a0, 39              /* 'a' - 10 - '0' */
2:      addi    a0, a0, 48              /* '0' */
        call    putc
        addi    s1, s1, -4
        bgez    s1, 1b
        li      a0, 32                  /* ' ' */
        call    putc
        ld      ra, 0(sp)
        ld      s0, 8(sp)
        ld      s1, 16(sp)
        addi    sp, sp, 32
        ret

putnl:
        addi    sp, sp, -16
        sd      ra, 0(sp)
        li      a0, 10
        call    putc
        ld      ra, 0(sp)
        addi    sp, sp, 16
        ret

/* a0 = character */
putc:
        la      a1, semichar
        sb      a0, 0(a1)
        li      a0, 0x03                /* SYS_WRITEC */
        .balign 16
        slli    zero, zero, 0x1f
        ebreak
        srai    zero, zero, 0x7
        ret

/* exit code in a0 */
_exit:
        la      a1, semiargs
        li      t0, 0x20026             /* ADP_Stopped_ApplicationExit */
        sd      t0, 0(a1)
        sd      a0, 8(a1)
        li      a0, 0x20                /* TARGET_SYS_EXIT_EXTENDED */

        .balign 16
        slli    zero, zero, 0x1f
        ebreak
        srai    zero, zero, 0x7
        j       .

        .data
        .balign 16
semiargs:
        .space  16
semichar:
        .space  8

        .balign 8
        /* enable bit, level to run at, whether it must be counted */
cells:
        .word   ITRIG_M,  AT_M,  1
        .word   ITRIG_M,  AT_S,  0
        .word   ITRIG_M,  AT_U,  0
        .word   ITRIG_S,  AT_M,  0
        .word   ITRIG_S,  AT_S,  1
        .word   ITRIG_S,  AT_U,  0
        .word   ITRIG_U,  AT_M,  0
        .word   ITRIG_U,  AT_S,  0
        .word   ITRIG_U,  AT_U,  1
        .word   ITRIG_VS, AT_VS, 1
        .word   ITRIG_VS, AT_VU, 0
        .word   ITRIG_VU, AT_VS, 0
        .word   ITRIG_VU, AT_VU, 1
        /* a virtualised level consults only the VS and VU bits */
        .word   ITRIG_S,  AT_VS, 0
        .word   ITRIG_U,  AT_VU, 0
        .word   ITRIG_M,  AT_VS, 0
        /* and a non-virtualised level consults only U, S and M */
        .word   ITRIG_VS, AT_S,  0
        .word   ITRIG_VU, AT_U,  0
        .word   0,        AT_END, 0

        .balign 8
diffcells:
        .word   ITRIG_M,  AT_M
        .word   ITRIG_S,  AT_S
        .word   ITRIG_U,  AT_U
        .word   ITRIG_VS, AT_VS
        .word   ITRIG_VU, AT_VU
        .word   0,        AT_END

        .bss
        .balign 16
stack:
        .space  4096
stack_top:
