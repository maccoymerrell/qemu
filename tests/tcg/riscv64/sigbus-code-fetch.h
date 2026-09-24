/*
 * Shared scaffolding for the guest-code-read SIGBUS tests.
 *
 * adjust_signal_pc() reports MMU_INST_FETCH for helper_retaddr == 1 --
 * the cpu_ld*_code() case -- and clears the pc to say the unwinder must
 * not run, because the guest pc is already correct.  host_sigsegv_handler()
 * and host_sigbus_handler() then ask whether that pc lies inside the code
 * gen buffer and treat "no" as a host bug worth dying for; a cleared pc
 * never does, so the question may only be asked for an access type that
 * is not MMU_INST_FETCH.
 *
 * Zcmt's cm.jalt reads its jump-vector-table entry with cpu_ld*_code()
 * from inside a helper, and jvt is an unprivileged CSR, so the address of
 * that read is entirely guest-chosen.  Aim it at a page of a file mapping
 * that lies past the end of the file and the host read raises SIGBUS with
 * BUS_ADRERR.
 *
 * Freestanding on purpose: reaching cm.jalt at all needs a CPU without D,
 * because trans_c_fsd() accepts the same encoding whenever D and C are
 * both present, and a glibc built for lp64d cannot start on such a CPU.
 *
 * Copyright (c) 2026 Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SIGBUS_CODE_FETCH_H
#define SIGBUS_CODE_FETCH_H

typedef unsigned long ul;

#define SYS_write           64
#define SYS_exit_group      94
#define SYS_rt_sigaction    134
#define SYS_mmap            222
#define SYS_memfd_create    279

#define SIGBUS              7

#define PROT_READ           1
#define PROT_EXEC           4
#define MAP_PRIVATE         2

static inline long sys(long n, long a, long b, long c, long d, long e, long f)
{
    register long a7 __asm__("a7") = n;
    register long a0 __asm__("a0") = a;
    register long a1 __asm__("a1") = b;
    register long a2 __asm__("a2") = c;
    register long a3 __asm__("a3") = d;
    register long a4 __asm__("a4") = e;
    register long a5 __asm__("a5") = f;

    __asm__ __volatile__("ecall"
                         : "+r"(a0)
                         : "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5),
                           "r"(a7)
                         : "memory");
    return a0;
}

static void say(const char *s, long len)
{
    sys(SYS_write, 1, (long)s, len, 0, 0, 0);
}

static void leave(int status)
{
    sys(SYS_exit_group, status, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static void die(const char *s, long len)
{
    say(s, len);
    leave(2);
}

/* asm-generic struct sigaction: riscv has no sa_restorer. */
struct kernel_sigaction {
    ul handler;
    ul flags;
    ul mask;
};

static void catch_sigbus(void (*handler)(int))
{
    struct kernel_sigaction sa = { (ul)handler, 0, 0 };

    if (sys(SYS_rt_sigaction, SIGBUS, (long)&sa, 0,
            sizeof(sa.mask), 0, 0) < 0) {
        die("rt_sigaction failed\n", 20);
    }
}

/*
 * One page of a zero-length memfd.  Nothing in it is backed, so any host
 * read of it raises SIGBUS/BUS_ADRERR.  The address is page aligned, so
 * jvt's low six bits -- its mode field -- are zero, which is the only
 * mode cm.jalt accepts.
 */
static ul unbacked_page(void)
{
    long fd, p;

    fd = sys(SYS_memfd_create, (long)"jvt", 0, 0, 0, 0, 0);
    if (fd < 0) {
        die("memfd_create failed\n", 20);
    }

    p = sys(SYS_mmap, 0, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (p > -4096 && p < 0) {
        die("mmap failed\n", 12);
    }
    return (ul)p;
}

static void set_jump_vector(ul jvt)
{
    __asm__ __volatile__("csrw 0x17, %0" : : "r"(jvt));
}

/* cm.jalt <index>: 101 000 iiiiiiii 10.  Reads 8 bytes at jvt + index * 8. */
#define CM_JALT_32 ".short 0xa082"

#endif /* SIGBUS_CODE_FETCH_H */
