/*
 * cst_attach — run an unmodified target so the ChampSim Tracer can attach.
 *
 * The plugin opens its trace window when it observes the marker sequence
 * (champsim_marker.h) execute, and pins the window to the address space the
 * marker runs in.  The marker therefore has to execute inside the target's
 * own address space.  This launcher gets it there for an arbitrary,
 * unmodified, statically- OR dynamically-linked binary by injecting it at
 * the entry point right after execve, via ptrace:
 *
 *   fork; child: PTRACE_TRACEME, execvp(target)
 *   parent: wait for the exec-stop  (target now mapped, stopped at its first
 *           userspace instruction, IN ITS OWN address space)
 *           save the bytes at the entry PC; poke the marker sequence there
 *           run the whole sequence      -> plugin observes it, pins ASID
 *           restore the original bytes and the registers; detach
 *           target runs from its real entry, on-disk binary never touched
 *
 * Why ptrace and not LD_PRELOAD: a preload-constructor only works for
 * dynamic binaries (no loader runs a static one), whereas ptrace reaches
 * into the post-execve image regardless of linkage.  Why not a launcher
 * that runs the marker then execs the target: execve replaces the address
 * space, so the marker's ASID would be the launcher's, not the target's.
 *
 * Portability.  The injector is the only OS/arch-specific piece, isolated
 * behind a three-call backend (regs_get/regs_set/regs_pc, encode_patch,
 * run_patch) selected by CST_ATTACH_ARCH_*.  Linux backends exist for
 * x86/x86-64, AArch64, RV64 and little-endian 32-bit MIPS — the four ISAs
 * the tracer targets.  A non-Linux guest is a new backend (Windows debug
 * API, macOS Mach, BSD ptrace) plus a per-arch marker encoding in
 * champsim_marker.h — not a redesign.  Unsupported host/arch combinations
 * fail loudly at build or run rather than silently mis-attaching.
 *
 * Two ways to run the injected sequence, one per backend family:
 *
 *   x86 single-steps it.  PTRACE_SINGLESTEP is backed by EFLAGS.TF, which
 *   every x86 kernel exposes, and the sequence is CST_MARKER_SEQ_LEN
 *   instructions long.
 *
 *   The fixed-width ISAs append a trap instruction after the sequence and
 *   PTRACE_CONT to it.  Single-step is not a portable primitive: RISC-V
 *   has no architectural single-step usable from S-mode (Linux answers
 *   PTRACE_SINGLESTEP with -EIO, which is why gdb software-steps RISC-V),
 *   and stepping is in any case six stops instead of one.  PTRACE_CONT and
 *   a breakpoint trap are universally available, and they let the marker's
 *   instructions retire back-to-back, which is exactly the adjacency the
 *   plugin's execution-time detector looks for.  All three trap handlers
 *   (arm64 brk_handler, riscv do_trap_break, mips do_bp with break code 0)
 *   report SIGTRAP with the PC left ON the trap instruction, so the stop
 *   PC is a positive check that the whole sequence executed.
 *
 * Instruction-cache coherency after patching text is the kernel's job on
 * every one of these ISAs: PTRACE_POKETEXT lands in access_process_vm(),
 * whose copy_to_user_page() is defined to flush the icache for the written
 * range (arm64 flush_ptrace_access, riscv/mips flush_icache_user_page).
 * That is why the patch goes through POKETEXT rather than a /proc/pid/mem
 * write.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * sched_setaffinity() and the CPU_SET/CPU_ZERO macros (used to pin the
 * traced process to a core) live behind the GNU extensions.  This file is
 * compiled standalone and statically for staging into a guest rootfs, so
 * it must request them itself rather than lean on a build system defining
 * _GNU_SOURCE; the define has to precede the first system header.  Guard
 * it so a build system that already passes -D_GNU_SOURCE (meson does)
 * does not trip a -Werror redefinition.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../champsim_marker.h"

/*
 * Backend selection.  One CST_ATTACH_ARCH_* is defined for a supported
 * host/arch pair; everything below keys off it.  MIPS is gated on
 * little-endian because cst_marker_mips_encode_seq_imm() emits a
 * little-endian word stream (the encoding the mipsel target executes) —
 * on a big-endian MIPS guest those bytes would decode as garbage, so the
 * honest answer there is "unsupported" rather than a silent mis-inject.
 */
#if defined(__linux__)
# if defined(__x86_64__) || defined(__i386__)
#  define CST_ATTACH_ARCH_X86 1
# elif defined(__aarch64__)
#  define CST_ATTACH_ARCH_A64 1
# elif defined(__riscv) && __riscv_xlen == 64
#  define CST_ATTACH_ARCH_RISCV 1
# elif defined(__mips__) && defined(__MIPSEL__)
#  define CST_ATTACH_ARCH_MIPS 1
# endif
#endif

#if defined(CST_ATTACH_ARCH_X86) || defined(CST_ATTACH_ARCH_A64) || \
    defined(CST_ATTACH_ARCH_RISCV) || defined(CST_ATTACH_ARCH_MIPS)
#define CST_ATTACH_SUPPORTED 1
#else
#define CST_ATTACH_SUPPORTED 0
#endif

#if CST_ATTACH_SUPPORTED

#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <sched.h>
#include <unistd.h>

#if defined(CST_ATTACH_ARCH_X86) || defined(CST_ATTACH_ARCH_A64)
/* x86 and aarch64 both get struct user_regs_struct from glibc. */
#include <sys/user.h>
#endif
#if defined(CST_ATTACH_ARCH_RISCV)
/* riscv's glibc <sys/user.h> does not declare struct user_regs_struct;
 * the kernel uapi header is where it lives (pc is its first member). */
#include <asm/ptrace.h>
#endif
#if defined(CST_ATTACH_ARCH_MIPS)
/* uapi <asm/ptrace.h> defines the PTRACE_PEEKUSER/POKEUSER register
 * indices: 0..31 are the GPRs and PC (== 64) is cp0_epc. */
#include <asm/ptrace.h>
#endif
#if defined(CST_ATTACH_ARCH_A64) || defined(CST_ATTACH_ARCH_RISCV)
#include <sys/uio.h>       /* struct iovec, for PTRACE_GETREGSET */
#include <elf.h>           /* NT_PRSTATUS */
#endif

/* ptrace POKETEXT/PEEKTEXT operate on word granularity. */
typedef unsigned long cst_word;
#define CST_WORD sizeof(cst_word)

/* Read @len bytes at guest address @addr from the traced child @pid. */
static int peek_bytes(pid_t pid, unsigned long addr, uint8_t *buf, size_t len)
{
    for (size_t off = 0; off < len; off += CST_WORD) {
        errno = 0;
        long w = ptrace(PTRACE_PEEKTEXT, pid, addr + off, 0);
        if (w == -1 && errno) {
            return -1;
        }
        size_t n = (len - off < CST_WORD) ? len - off : CST_WORD;
        memcpy(buf + off, &w, n);
    }
    return 0;
}

/* Write @len bytes to guest address @addr in the traced child @pid,
 * preserving the bytes beyond @len within the final partial word. */
static int poke_bytes(pid_t pid, unsigned long addr, const uint8_t *buf,
                      size_t len)
{
    for (size_t off = 0; off < len; off += CST_WORD) {
        cst_word w;
        size_t n = (len - off < CST_WORD) ? len - off : CST_WORD;
        if (n < CST_WORD) {
            /* Partial trailing word: read-modify-write so we don't clobber
             * the instruction bytes that follow the injection site. */
            errno = 0;
            long cur = ptrace(PTRACE_PEEKTEXT, pid, addr + off, 0);
            if (cur == -1 && errno) {
                return -1;
            }
            w = (cst_word)cur;
        }
        memcpy(&w, buf + off, n);
        if (ptrace(PTRACE_POKETEXT, pid, addr + off, (void *)w) == -1) {
            return -1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ *
 * Per-arch backend.
 *
 * Three things vary across ISAs and nothing else does:
 *
 *   cst_regs / regs_get / regs_set / regs_pc
 *       save, restore and read the PC out of the child's register state.
 *       The saved state must cover everything the injected sequence
 *       clobbers, because the target has to resume from its real entry
 *       with the register file the kernel handed it at execve.
 *   encode_patch()
 *       the bytes written at the entry: the marker sequence, plus (on the
 *       trap-terminated backends) the trap that ends it.
 *   run_patch()
 *       run the patch and stop with the whole marker sequence retired.
 *
 * CST_ATTACH_PATCH_BYTES is the patch length, which is also how many
 * original bytes are saved and restored.
 * ------------------------------------------------------------------ */

#if defined(CST_ATTACH_ARCH_X86)

#define CST_ATTACH_ARCH_NAME     "x86"
#define CST_ATTACH_PATCH_BYTES   CST_MARKER_X86_SEQ_BYTES
#define CST_ATTACH_ENTRY_ALIGN   1u        /* x86 insns are unaligned */

struct cst_regs { struct user_regs_struct r; };

static int regs_get(pid_t pid, struct cst_regs *s)
{
    return ptrace(PTRACE_GETREGS, pid, 0, &s->r) == -1 ? -1 : 0;
}

static int regs_set(pid_t pid, const struct cst_regs *s)
{
    /* PTRACE_SETREGS takes a non-const pointer; the kernel only reads it. */
    return ptrace(PTRACE_SETREGS, pid, 0, (void *)&s->r) == -1 ? -1 : 0;
}

static unsigned long regs_pc(const struct cst_regs *s)
{
#if defined(__x86_64__)
    return s->r.rip;
#else
    return s->r.eip;
#endif
}

static void encode_patch(uint8_t *out)
{
    cst_marker_x86_encode_seq(out);
}

/*
 * Single-step exactly the marker insns so the plugin observes the full
 * sequence execute (and arms/pins on the last).  Each is a 5-byte
 * `mov $imm,%eax`; CST_MARKER_SEQ_LEN steps cover them.
 */
static int run_patch(pid_t pid, unsigned long entry)
{
    (void)entry;
    for (unsigned i = 0; i < CST_MARKER_SEQ_LEN; i++) {
        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1) {
            perror("cst_attach: PTRACE_SINGLESTEP");
            return -1;
        }
        int status;
        if (waitpid(pid, &status, 0) < 0) {
            perror("cst_attach: waitpid(singlestep)");
            return -1;
        }
        if (WIFEXITED(status)) {
            fprintf(stderr, "cst_attach: target exited during marker step\n");
            return -1;
        }
    }
    return 0;
}

#else   /* the fixed-width, trap-terminated backends */

/*
 * aarch64 / RV64 / mipsel all encode the marker as CST_MARKER_SEQ_LEN
 * two-instruction immediate-load pairs (champsim_marker.h), so the patch
 * is that sequence followed by one 4-byte trap.
 */
#define CST_ATTACH_TRAP_BYTES    4u
#define CST_ATTACH_PATCH_BYTES   (CST_MARKER_PAIR_SEQ_BYTES + \
                                  CST_ATTACH_TRAP_BYTES)

#if defined(CST_ATTACH_ARCH_A64)

#define CST_ATTACH_ARCH_NAME     "aarch64"
#define CST_ATTACH_TRAP_INSN     0xd4200000u    /* brk #0 */
#define CST_ATTACH_ENTRY_ALIGN   4u

/* NT_PRSTATUS is struct user_regs_struct: x0..x30, sp, pc, pstate. */
struct cst_regs { struct user_regs_struct r; };

#elif defined(CST_ATTACH_ARCH_RISCV)

#define CST_ATTACH_ARCH_NAME     "riscv64"
#define CST_ATTACH_TRAP_INSN     0x00100073u    /* ebreak (base ISA, 4-byte;
                                                 * never the 2-byte c.ebreak,
                                                 * so the patch stays a whole
                                                 * number of 4-byte slots) */
/*
 * IALIGN is 16 on any hart implementing the C extension, so a 32-bit
 * instruction is legal at any 2-byte boundary and RISC-V entry points are
 * only guaranteed 2-byte aligned — the rv64gc ld.so this attaches to
 * starts at one (observed: 0x...b06).  Requiring 4 here would reject every
 * dynamically linked rv64gc target.  A target built without C always has a
 * 4-aligned entry anyway, so accepting 2 never loosens the guarantee that
 * the patch lands on an instruction boundary.
 */
#define CST_ATTACH_ENTRY_ALIGN   2u

/* NT_PRSTATUS is struct user_regs_struct from uapi asm/ptrace.h. */
struct cst_regs { struct user_regs_struct r; };

#else   /* CST_ATTACH_ARCH_MIPS */

#define CST_ATTACH_ARCH_NAME     "mipsel"
#define CST_ATTACH_TRAP_INSN     0x0000000du    /* break (code 0) */
#define CST_ATTACH_ENTRY_ALIGN   4u

/*
 * MIPS reads and writes single registers by uapi index instead of a
 * regset.  NT_PRSTATUS on MIPS is an elf_gregset_t whose layout is spelled
 * out in the kernel's non-uapi <asm/reg.h> (the MIPS32_EF_* offsets), so
 * it is not something userspace can address portably; PTRACE_PEEKUSER's
 * index space *is* uapi (asm/ptrace.h: 0..31 GPRs, PC == 64) and is what
 * gdb uses.  Two indices cover everything the injection touches: PC, and
 * $t0 == GPR 8, the register the marker's lui/ori pair loads.
 */
#define CST_ATTACH_MIPS_T0       8

struct cst_regs { unsigned long pc; unsigned long t0; };

#endif  /* per-arch struct cst_regs */

#if defined(CST_ATTACH_ARCH_A64) || defined(CST_ATTACH_ARCH_RISCV)

static int regs_get(pid_t pid, struct cst_regs *s)
{
    struct iovec io = { .iov_base = &s->r, .iov_len = sizeof(s->r) };
    return ptrace(PTRACE_GETREGSET, pid, (void *)(unsigned long)NT_PRSTATUS,
                  &io) == -1 ? -1 : 0;
}

static int regs_set(pid_t pid, const struct cst_regs *s)
{
    struct iovec io = { .iov_base = (void *)&s->r, .iov_len = sizeof(s->r) };
    return ptrace(PTRACE_SETREGSET, pid, (void *)(unsigned long)NT_PRSTATUS,
                  &io) == -1 ? -1 : 0;
}

static unsigned long regs_pc(const struct cst_regs *s)
{
    return (unsigned long)s->r.pc;
}

#else   /* CST_ATTACH_ARCH_MIPS */

static int regs_get(pid_t pid, struct cst_regs *s)
{
    errno = 0;
    long pc = ptrace(PTRACE_PEEKUSER, pid, (void *)(unsigned long)PC, 0);
    if (pc == -1 && errno) {
        return -1;
    }
    errno = 0;
    long t0 = ptrace(PTRACE_PEEKUSER, pid,
                     (void *)(unsigned long)CST_ATTACH_MIPS_T0, 0);
    if (t0 == -1 && errno) {
        return -1;
    }
    s->pc = (unsigned long)pc;
    s->t0 = (unsigned long)t0;
    return 0;
}

static int regs_set(pid_t pid, const struct cst_regs *s)
{
    if (ptrace(PTRACE_POKEUSER, pid, (void *)(unsigned long)PC,
               (void *)s->pc) == -1) {
        return -1;
    }
    if (ptrace(PTRACE_POKEUSER, pid, (void *)(unsigned long)CST_ATTACH_MIPS_T0,
               (void *)s->t0) == -1) {
        return -1;
    }
    return 0;
}

static unsigned long regs_pc(const struct cst_regs *s)
{
    return s->pc;
}

#endif  /* register access */

static void encode_patch(uint8_t *out)
{
#if defined(CST_ATTACH_ARCH_A64)
    cst_marker_a64_encode_seq_imm(out, CST_MARKER_MAGIC);
#elif defined(CST_ATTACH_ARCH_RISCV)
    cst_marker_riscv_encode_seq_imm(out, CST_MARKER_MAGIC);
#else
    cst_marker_mips_encode_seq_imm(out, CST_MARKER_MAGIC);
#endif
    cst_marker_put_u32le(out + CST_MARKER_PAIR_SEQ_BYTES,
                         CST_ATTACH_TRAP_INSN);
}

/*
 * Let the whole sequence retire in one go and stop on the trailing trap.
 * The marker instructions execute back-to-back at user privilege in the
 * target's address space, which is precisely the run the plugin's
 * execution-time detector recognises.
 *
 * A stop that is not our trap is a signal the fresh, handler-less child
 * had no business receiving; swallow it (deliver 0 rather than re-raise,
 * which would kill a process with no handlers installed) and continue,
 * bounded so a pathological guest cannot spin here forever.
 */
static int run_patch(pid_t pid, unsigned long entry)
{
    const unsigned MAX_SPURIOUS = 16;
    unsigned spurious = 0;

    for (;;) {
        if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
            perror("cst_attach: PTRACE_CONT");
            return -1;
        }
        int status;
        if (waitpid(pid, &status, 0) < 0) {
            perror("cst_attach: waitpid(marker)");
            return -1;
        }
        if (!WIFSTOPPED(status)) {
            fprintf(stderr,
                    "cst_attach: target exited during marker sequence\n");
            return -1;
        }
        if (WSTOPSIG(status) == SIGTRAP) {
            break;
        }
        if (++spurious > MAX_SPURIOUS) {
            fprintf(stderr, "cst_attach: target kept stopping on signal %d "
                    "instead of the marker trap\n", WSTOPSIG(status));
            return -1;
        }
    }

    /*
     * The stop PC is the proof the sequence ran: all three trap handlers
     * leave it on the trap instruction, i.e. exactly one full marker
     * sequence past the entry.  Anything else means the target did not
     * execute what we wrote, so refuse rather than resume it with an
     * unknown amount of the patch retired.
     */
    struct cst_regs at_trap;
    if (regs_get(pid, &at_trap) != 0) {
        perror("cst_attach: read regs at marker trap");
        return -1;
    }
    unsigned long want = entry + CST_MARKER_PAIR_SEQ_BYTES;
    if (regs_pc(&at_trap) != want) {
        fprintf(stderr, "cst_attach[" CST_ATTACH_ARCH_NAME "]: marker trap at "
                "0x%lx, expected 0x%lx (sequence did not execute as "
                "written)\n", regs_pc(&at_trap), want);
        return -1;
    }
    return 0;
}

#endif  /* backend family */

/*
 * Inject the marker sequence at the target's entry, run it, then restore.
 * At the exec-stop the child is at its first userspace instruction in its
 * own address space; the marker runs there, so the plugin pins to the
 * target's ASID.  Returns 0 on success.
 */
static int inject_marker_at_entry(pid_t pid)
{
    struct cst_regs saved_regs;
    if (regs_get(pid, &saved_regs) != 0) {
        perror("cst_attach: read entry registers");
        return -1;
    }
    unsigned long entry = regs_pc(&saved_regs);

    /* The patch has to land on an instruction boundary, which on the
     * fixed-width backends is a per-arch alignment (CST_ATTACH_ENTRY_ALIGN;
     * see the RISC-V note for why it is 2 there, not 4).  An entry that
     * does not meet it is not an entry point, and the patch would decode
     * as garbage. */
    if (CST_ATTACH_ENTRY_ALIGN > 1 && (entry & (CST_ATTACH_ENTRY_ALIGN - 1))) {
        fprintf(stderr, "cst_attach[" CST_ATTACH_ARCH_NAME "]: entry 0x%lx is "
                "not %u-byte aligned\n", entry, CST_ATTACH_ENTRY_ALIGN);
        return -1;
    }

    uint8_t patch[CST_ATTACH_PATCH_BYTES];
    encode_patch(patch);

    uint8_t orig[CST_ATTACH_PATCH_BYTES];
    if (peek_bytes(pid, entry, orig, sizeof(orig)) != 0) {
        perror("cst_attach: read entry bytes");
        return -1;
    }
    if (poke_bytes(pid, entry, patch, sizeof(patch)) != 0) {
        perror("cst_attach: write marker");
        return -1;
    }

    if (run_patch(pid, entry) != 0) {
        return -1;
    }

    /* Restore the original entry bytes and rewind the PC so the target
     * runs from its real first instruction, fully intact. */
    if (poke_bytes(pid, entry, orig, sizeof(orig)) != 0) {
        perror("cst_attach: restore entry bytes");
        return -1;
    }
    if (regs_set(pid, &saved_regs) != 0) {
        perror("cst_attach: restore entry registers");
        return -1;
    }
    return 0;
}

/*
 * Confine the target to a single guest CPU (default for pinned-process
 * tracing).  The ChampSim Tracer is single-address-space: a marker-mode
 * trace pins one process, and thread_id follows the software thread across
 * whatever core the guest scheduler picks — but only user-code identity is
 * architecturally recoverable across a migration, since kernel code carries
 * no per-thread register.  Pinning the target to one guest CPU removes
 * migration entirely, so per-thread attribution is trivially stable and the
 * plugin's migration-detect guard stays quiet.  This is a guest-side,
 * Linux-specific action, which is why it lives in the OS-specific injector.
 * Best-effort: a failure (e.g. the CPU is offline) is a warning, not fatal —
 * the trace still runs, just without the confinement guarantee.
 */
static void pin_target_to_cpu(pid_t pid, int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(pid, sizeof(set), &set) == -1) {
        fprintf(stderr, "cst_attach: warning: could not pin target to guest "
                "CPU %d (%s); per-thread attribution may be unstable if the "
                "guest migrates it across vCPUs\n", cpu, strerror(errno));
    }
}

static int run(char **argv, int pin_cpu)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("cst_attach: fork");
        return 1;
    }
    if (pid == 0) {
        /* Child: become traceable, drop ASLR so the entry / stack are
         * reproducible (matches the tracer's setarch -R guidance), exec. */
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
            perror("cst_attach: PTRACE_TRACEME");
            _exit(127);
        }
        personality(ADDR_NO_RANDOMIZE);
        execvp(argv[0], argv);
        perror("cst_attach: execvp");
        _exit(127);
    }

    /* Parent: first stop is the exec-stop (target mapped, at its entry, in
     * its own address space). */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("cst_attach: waitpid(exec-stop)");
        return 1;
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "cst_attach: target did not stop at exec\n");
        return 1;
    }

    /* The target is now its own post-execve image, stopped at its entry.
     * Confine it to one guest CPU (unless disabled) BEFORE it runs, so it
     * never migrates and per-thread attribution stays clean. */
    if (pin_cpu >= 0) {
        pin_target_to_cpu(pid, pin_cpu);
    }

    if (inject_marker_at_entry(pid) != 0) {
        ptrace(PTRACE_KILL, pid, 0, 0);
        return 1;
    }

    /* Detach and let the target run to completion under the tracer. */
    if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
        perror("cst_attach: PTRACE_DETACH");
        return 1;
    }
    if (waitpid(pid, &status, 0) < 0) {
        perror("cst_attach: waitpid(target)");
        return 1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

#endif /* CST_ATTACH_SUPPORTED */

static void usage(void)
{
    fprintf(stderr,
        "usage: cst_attach [--pin-cpu N | --no-pin] [--] <target> [args...]\n"
        "\n"
        "Runs <target>, injecting the ChampSim Tracer marker at its entry\n"
        "point so the plugin attaches and pins to its address space.\n"
        "Intended to run under qemu(-system) with the plugin loaded in\n"
        "trace_window=marker mode.\n"
        "\n"
        "  --pin-cpu N   Confine the target to guest CPU N (default: 0).\n"
        "                The tracer is single-address-space, so a target\n"
        "                pinned to one core never migrates and its\n"
        "                per-thread attribution is stable.\n"
        "  --no-pin      Do NOT confine the target (let the guest scheduler\n"
        "                place it freely).  A pinned process that then\n"
        "                migrates across vCPUs is outside the clean\n"
        "                attribution envelope; the plugin warns when it\n"
        "                observes this.\n");
}

int main(int argc, char **argv)
{
    /* Pin the target to one guest CPU by default (see pin_target_to_cpu);
     * -1 disables confinement. */
    int pin_cpu = 0;
    int i = 1;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "--")) {
            i++;
            break;
        } else if (!strcmp(argv[i], "--no-pin")) {
            pin_cpu = -1;
        } else if (!strcmp(argv[i], "--pin-cpu")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "cst_attach: --pin-cpu needs an argument\n");
                return 2;
            }
            pin_cpu = atoi(argv[++i]);
            if (pin_cpu < 0) {
                fprintf(stderr, "cst_attach: --pin-cpu must be >= 0\n");
                return 2;
            }
        } else if (argv[i][0] == '-' && argv[i][1] != '\0') {
            fprintf(stderr, "cst_attach: unknown option '%s'\n", argv[i]);
            usage();
            return 2;
        } else {
            break;   /* first non-option token is the target */
        }
    }
    if (i >= argc) {
        usage();
        return 2;
    }
#if CST_ATTACH_SUPPORTED
    return run(argv + i, pin_cpu);
#else
    (void)pin_cpu;
    fprintf(stderr,
        "cst_attach: unsupported host/arch (need Linux + one of x86/x86-64,\n"
        "aarch64, rv64, little-endian mips32).\n"
        "The ptrace injector is the only platform-specific piece; add a\n"
        "backend in this file + a marker encoding in champsim_marker.h.\n");
    (void)argv;
    return 3;
#endif
}
