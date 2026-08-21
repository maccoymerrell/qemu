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
 *           poke the marker sequence at the entry PC and PERSIST it
 *             (content-as-gate: the window re-reads those bytes at every
 *             context switch)
 *           x86: single-step the sequence -> plugin observes it, pins ASID;
 *             restore the registers, resume just past the marker; detach
 *           aarch64/rv64/mipsel: detach — the released child executes the
 *             persisted marker itself (plugin observes it, pins ASID) and
 *             falls through into its own code at entry + marker bytes
 *           on-disk binary never touched (the patch is in the live image)
 *
 * Why ptrace and not LD_PRELOAD: a preload-constructor only works for
 * dynamic binaries (no loader runs a static one), whereas ptrace reaches
 * into the post-execve image regardless of linkage.  Why not a launcher
 * that runs the marker then execs the target: execve replaces the address
 * space, so the marker's ASID would be the launcher's, not the target's.
 *
 * Portability.  The injector is the only OS/arch-specific piece, isolated
 * behind a small backend (regs_get/regs_pc + encode_patch everywhere;
 * regs_set/regs_set_pc/run_patch on x86, whose marker is parent-stepped)
 * selected by CST_ATTACH_ARCH_*.  Linux backends exist for
 * x86/x86-64, AArch64, RV64 and little-endian 32-bit MIPS — the four ISAs
 * the tracer targets.  A non-Linux guest is a new backend (Windows debug
 * API, macOS Mach, BSD ptrace) plus a per-arch marker encoding in
 * champsim_marker.h — not a redesign.  Unsupported host/arch combinations
 * fail loudly at build or run rather than silently mis-attaching.
 *
 * INJECTION CHOREOGRAPHY — two backend families, and why neither leaves a
 * transient byte where a captured TB can see it:
 *
 *   x86 single-steps the sequence.  PTRACE_SINGLESTEP is backed by
 *   EFLAGS.TF, which every x86 kernel exposes; CST_MARKER_SEQ_LEN steps
 *   retire the marker under the parent's control, the stop PC proves it
 *   ran, and the register file (the marker clobbers %eax) is restored
 *   exactly, with the resume PC placed on the first instruction past the
 *   persisted marker.  The patch is the marker alone — nothing transient
 *   is ever in the live image.
 *
 *   The fixed-width ISAs (aarch64 / RV64 / mipsel) POKE-AND-RELEASE: the
 *   patch is the marker sequence alone, and after writing it the parent
 *   simply detaches.  The child executes the persisted marker at its
 *   entry and falls through into its own first unreplaced instruction at
 *   entry + CST_ATTACH_MARKER_SEQ_BYTES — exactly where the old
 *   trap-based choreography used to place the resume PC by hand.  No
 *   post-marker stop exists, and none is load-bearing:
 *
 *     - PC placement is the natural fall-through;
 *     - there is no trailing trap slot to restore;
 *     - the only register-file damage is the marker's scratch register
 *       (a64 w0 / riscv a0 / mips $t0) left holding the final marker
 *       immediate.  At execve the kernel hands _start zeroed GPRs and no
 *       ABI grants a scratch register meaning at the entry point, so an
 *       entry that READS it before writing it is already outside the
 *       process-start contract — a strictly weaker imposition than the
 *       one this injector openly makes anyway (the first
 *       CST_ATTACH_MARKER_SEQ_BYTES of entry code are replaced by the
 *       persisted marker and never execute).  The canonical entries
 *       (glibc _start, ld.so _start on all three ISAs) write their first
 *       argument register before reading it.
 *
 *   These backends previously appended a breakpoint trap (arm64 brk #0,
 *   riscv ebreak, mips break) after the sequence, PTRACE_CONTed to it,
 *   and restored the trap slot at the stop.  That choreography is GONE,
 *   and must not come back in any placement: QEMU translates whole TBs,
 *   and the marker's TB — translated the instant the sequence first
 *   executes, i.e. BEFORE any ptrace stop can restore anything — extends
 *   past the sequence into whatever bytes follow it.  The trap byte was
 *   therefore captured into a wire template (template_raw_bytes flagged
 *   the mips break word 0x0000000d at entry+24 against the target's
 *   image), and no stop placed after the marker can avoid the same
 *   capture, because the stop's own instruction bytes would sit in a
 *   translated-and-captured TB just the same.  Single-step is not a
 *   portable escape either: RISC-V Linux answers PTRACE_SINGLESTEP with
 *   -EIO (gdb software-steps it, which is the same trap problem), and
 *   MIPS has no hardware trace bit.  What the stop bought — the stop-PC
 *   proof of retirement — is carried by the plugin itself now: the
 *   marker's execution is what opens the trace window, so a run that
 *   produced a window is the proof, and a failed injection is loud at
 *   the poke.
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
 * What varies across ISAs and nothing else does:
 *
 *   cst_regs / regs_get / regs_pc
 *       read the child's register state (the entry PC lives there).
 *   regs_set / regs_set_pc              (x86 only)
 *       restore the register file after single-stepping the marker and
 *       place the resume PC past it.  The fixed-width backends have no
 *       post-marker stop (poke-and-release; see the header comment), so
 *       they never write registers at all.
 *   encode_patch()
 *       the bytes written at the entry: the marker sequence, nothing
 *       else.  A trailing trap is forbidden — its byte lands inside the
 *       marker's translated-and-captured TB (header comment).
 *   run_patch()                          (x86 only)
 *       single-step the marker to retirement under the parent's control.
 *
 * CST_ATTACH_PATCH_BYTES is the patch length; every patched byte is
 * persisted (content-as-gate), so nothing is saved or restored.
 * ------------------------------------------------------------------ */

#if defined(CST_ATTACH_ARCH_X86)

#define CST_ATTACH_ARCH_NAME     "x86"
#define CST_ATTACH_PATCH_BYTES   CST_MARKER_X86_SEQ_BYTES
/* The persisted portion of the patch (the marker; x86 has no trailing
 * trap, so it is the whole patch). */
#define CST_ATTACH_MARKER_SEQ_BYTES CST_MARKER_X86_SEQ_BYTES
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

static void regs_set_pc(struct cst_regs *s, unsigned long pc)
{
#if defined(__x86_64__)
    s->r.rip = pc;
#else
    s->r.eip = pc;
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

#else   /* the fixed-width, poke-and-release backends */

/*
 * aarch64 / RV64 / mipsel all encode the marker as CST_MARKER_SEQ_LEN
 * two-instruction immediate-load pairs (champsim_marker.h); the patch is
 * that sequence and nothing else, all of it persisted.
 */
#define CST_ATTACH_PATCH_BYTES   CST_MARKER_PAIR_SEQ_BYTES
/* The persisted portion of the patch — the whole of it. */
#define CST_ATTACH_MARKER_SEQ_BYTES CST_MARKER_PAIR_SEQ_BYTES

#if defined(CST_ATTACH_ARCH_A64)

#define CST_ATTACH_ARCH_NAME     "aarch64"
#define CST_ATTACH_ENTRY_ALIGN   4u

/* NT_PRSTATUS is struct user_regs_struct: x0..x30, sp, pc, pstate. */
struct cst_regs { struct user_regs_struct r; };

#elif defined(CST_ATTACH_ARCH_RISCV)

#define CST_ATTACH_ARCH_NAME     "riscv64"
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
#define CST_ATTACH_ENTRY_ALIGN   4u

/*
 * MIPS reads single registers by uapi index instead of a regset.
 * NT_PRSTATUS on MIPS is an elf_gregset_t whose layout is spelled out in
 * the kernel's non-uapi <asm/reg.h> (the MIPS32_EF_* offsets), so it is
 * not something userspace can address portably; PTRACE_PEEKUSER's index
 * space *is* uapi (asm/ptrace.h: 0..31 GPRs, PC == 64) and is what gdb
 * uses.  One index covers everything the injection touches: PC.  ($t0,
 * the marker's scratch register, is deliberately NOT saved/restored —
 * poke-and-release has no stop to restore it at; see the header comment
 * for why the residue is within the process-start contract.)
 */

struct cst_regs { unsigned long pc; };

#endif  /* per-arch struct cst_regs */

#if defined(CST_ATTACH_ARCH_A64) || defined(CST_ATTACH_ARCH_RISCV)

static int regs_get(pid_t pid, struct cst_regs *s)
{
    struct iovec io = { .iov_base = &s->r, .iov_len = sizeof(s->r) };
    return ptrace(PTRACE_GETREGSET, pid, (void *)(unsigned long)NT_PRSTATUS,
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
    s->pc = (unsigned long)pc;
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
}

#endif  /* backend family */

/*
 * Inject the marker sequence at the target's entry and PERSIST it.
 *
 * CONTENT-AS-GATE (system mode): the tracer's gate refresh re-reads the
 * START bytes at the latched vaddr on every committed address-space switch,
 * so the marker bytes must stay at that vaddr for the window to survive.
 * This injector therefore LEAVES the marker sequence patched at the entry
 * (it does NOT restore it — the earlier restore closed the window at the
 * first refresh).  Every patched byte is persisted marker; nothing
 * transient is ever written into the image (a trailing trap would be
 * captured into a wire template by whole-TB translation — see the header
 * comment).  How the sequence then executes is per family:
 *
 *   x86: single-stepped under the parent (run_patch), register file
 *   restored, resume PC placed at entry + CST_ATTACH_MARKER_SEQ_BYTES.
 *
 *   aarch64 / RV64 / mipsel: poke-and-release — the caller detaches and
 *   the child itself executes the persisted marker at its entry, falling
 *   through into its first unreplaced instruction at
 *   entry + CST_ATTACH_MARKER_SEQ_BYTES.  The marker's scratch register
 *   residue is within the process-start contract (header comment).
 *
 * Consequence, stated loudly: the target's original entry prologue
 * (CST_ATTACH_MARKER_SEQ_BYTES) is REPLACED by the persisted marker.  A
 * fully transparent capture — one that preserves the target's own prologue
 * byte-for-byte — requires relocating the real entry behind an mmap'd RX
 * scratch page and latching the marker there; that relocation, and an
 * injected mlock(2) to pin the marker page, are the remaining refinement.
 * Marker-page residency across refreshes otherwise relies on the guest
 * keeping the page resident (a no-swap initramfs — the validator's shape —
 * or `swapoff`); a gated context whose page pages out at a refresh gates
 * the capture off, which the plugin's `gated context lost marker page
 * residency` counter makes loud.
 *
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

    if (poke_bytes(pid, entry, patch, sizeof(patch)) != 0) {
        perror("cst_attach: write marker");
        return -1;
    }

#if defined(CST_ATTACH_ARCH_X86)
    /* Single-step the marker to retirement, then restore the register
     * file (the marker clobbered %eax) and advance the PC to the first
     * instruction past the persisted marker so the target resumes there
     * rather than re-executing it. */
    if (run_patch(pid, entry) != 0) {
        return -1;
    }
    struct cst_regs resume = saved_regs;
    regs_set_pc(&resume, entry + CST_ATTACH_MARKER_SEQ_BYTES);
    if (regs_set(pid, &resume) != 0) {
        perror("cst_attach: set resume registers");
        return -1;
    }
#endif
    /* Fixed-width backends: nothing left to do.  The detach in run()
     * releases the child at its entry; it executes the persisted marker
     * itself and falls through into its own code.  The proof the marker
     * ran is the plugin's: the sequence's execution is what opens the
     * trace window. */
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
