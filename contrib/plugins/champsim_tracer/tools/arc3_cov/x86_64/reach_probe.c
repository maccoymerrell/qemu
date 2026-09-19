/*
 * ARC 3 -- is this encoding REACHABLE by a QEMU x86_64 guest?
 *
 * The coverage report's reachability column decides whether a tracer
 * decode gap costs anything.  It used to be a guess off XED's EXTENSION
 * string, and the guess was wrong by 128 rows: the APX (EVEX-promoted)
 * forms of BMI1, BMI2, ADOX_ADCX, LZCNT, MOVBE, RAO, USER_MSR and the
 * rest keep their original extension name and carry APX only in their
 * ISA-SET, so a name test on the extension called every one of them
 * reachable.  QEMU TCG has no APX and executes none of them.
 *
 * So reachability is measured instead.  Each encoding is written into an
 * executable page, called, and the verdict is whether it ran: build this
 * for the guest and run it UNDER qemu-x86_64, where SIGILL is QEMU's TCG
 * front end refusing the bytes.
 *
 * A VICTIM MUST NOT BE ABLE TO END THE RUN (finding 250-G).  This probe
 * used to call every encoding in its own process, on its own stack,
 * behind a sigsetjmp.  That works only for encodings that fault.  An
 * encoding that TRANSFERS CONTROL walks straight past the longjmp:
 * measured 2026-09-19, `c9` (LEAVE) -- line 7893 of the 8,313-encoding
 * set -- unwound the harness's own frame and the trailing `ret` returned
 * out of main, so the probe exited 0 having reported 7,892 rows, and 421
 * encodings carried no verdict at all.  Exit status 0 is what made it
 * silent: nothing downstream could tell a finished sweep from a hijacked
 * one.  The same encoding does the same thing on native hardware.
 *
 * Two independent changes answer that, and both are needed:
 *
 *   ISOLATION.  Every encoding runs in a FORKED CHILD, and the verdict
 *   comes from waitpid's status rather than from a handler in the
 *   harness -- the aarch64 prober's pattern.  A victim can now kill only
 *   itself.  Inside the child the victim also gets its own stack, every
 *   qword of which holds the address of an exit-0 trampoline, so an
 *   encoding that returns, unwinds or pops its way out of the harness
 *   lands on the trampoline and is scored as having RUN, which is what it
 *   did.  RSP and RBP both point into that stack, so `leave; ret` is
 *   ordinary rather than fatal.  alarm() bounds an encoding that branches
 *   to itself: SIGALRM is a verdict, never a stall.
 *
 *   A COUNT.  Isolation removes the mechanism that was known; it cannot
 *   promise there is no other way to lose rows.  So the probe counts the
 *   encodings it read and the rows it wrote, and exits non-zero naming
 *   the shortfall if they differ.  reach_models.sh re-checks the same
 *   equality from outside, because a probe that dies mid-file cannot run
 *   its own epilogue -- which is exactly how 250-G stayed quiet.
 *
 * WHAT THIS CANNOT SEE, and the report must not claim it does: an
 * instruction QEMU implements only at CPL 0 raises SIGILL here for the
 * privilege, not for the opcode.  Corroborate those against
 * target/i386/tcg/decode-new.c.inc before quoting them -- at the time of
 * writing every SIGILL row is absent from that file entirely, so the two
 * agree, and a future divergence is a finding rather than a footnote.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>

/* The one way out of a child that did not fault.  Written as raw
 * instructions because the victim runs with the C stack replaced, so
 * nothing that expects a valid frame -- _exit() included -- may be
 * called from here. */
extern void reach_exit_trampoline(void);
__asm__(".text\n"
        ".globl reach_exit_trampoline\n"
        ".hidden reach_exit_trampoline\n"
        "reach_exit_trampoline:\n"
        "    xor %edi, %edi\n"
        "    mov $231, %eax\n"          /* __NR_exit_group */
        "    syscall\n"
        "    hlt\n");

#define VSTACK_BYTES  (256u * 1024u)
#define VSTACK_SLOTS  (VSTACK_BYTES / 8u)

/* Seconds a single encoding may run.  An encoding that branches to itself
 * would otherwise hold the sweep open forever; SIGALRM gives it a
 * verdict of its own instead (finding 250-D, in the per-encoding form). */
#define VICTIM_SECONDS 3

int main(void)
{
    char line[64];
    unsigned long population = 0, emitted = 0;
    uint8_t *page, *scratch;
    uint64_t *vstack;
    unsigned i;

    /* THE THREE REGIONS ARE SET UP ONCE, NOT PER ENCODING.  Only the
     * child ever writes them, and a child's writes are private to it, so
     * the parent's copy stays exactly as prepared here for the whole
     * sweep: scratch stays zero-filled and every stack slot keeps the
     * trampoline address.  Doing it per row instead costs three mmaps,
     * three munmaps and a 256 KiB store loop each time -- 2 GiB of
     * emulated stores across the set, for no difference in what is
     * measured. */
    page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    scratch = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    vstack = mmap(NULL, VSTACK_BYTES, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED || scratch == MAP_FAILED ||
        vstack == MAP_FAILED) {
        fprintf(stderr, "reach_probe: mmap failed\n");
        return 2;
    }
    /* Every return address the victim can reach is the trampoline. */
    for (i = 0; i < VSTACK_SLOTS; i++) {
        vstack[i] = (uint64_t)(uintptr_t)&reach_exit_trampoline;
    }

    printf("hex\texec\tsignal\n");
    while (fgets(line, sizeof line, stdin)) {
        unsigned n = 0;
        int caught = 0;
        pid_t pid;
        const char *p = line;

        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '#' || *p == '\n' || !*p) {
            continue;
        }
        population++;

        /* The previous encoding's bytes must not survive into this one:
         * an encoding longer than the hex given for it would eat the
         * trailing `ret` and run whatever followed. */
        memset(page, 0, 32);
        for (; p[0] && p[1] && isxdigit((unsigned char)p[0]) &&
               isxdigit((unsigned char)p[1]) && n < 15; p += 2) {
            char t[3] = { p[0], p[1], 0 };
            page[n++] = (uint8_t)strtoul(t, NULL, 16);
        }
        page[n] = 0xc3;                 /* ret */

        /* Nothing of ours may still be buffered when the child inherits
         * the stream, or a row is reported twice. */
        if (fflush(stdout) != 0) {
            fprintf(stderr, "reach_probe: stdout write failed at encoding "
                    "%lu\n", population);
            return 2;
        }

        pid = fork();
        if (pid < 0) {
            fprintf(stderr, "reach_probe: fork failed at encoding %lu\n",
                    population);
            return 2;
        }
        if (pid == 0) {
            /* MOST ENCODINGS IN THIS SET FAULT -- that is the measurement.
             * A faulting child is a crashing process, and on a host whose
             * core_pattern pipes to a crash handler that costs over a
             * second EACH: measured 2026-09-19, 50 ud2 encodings took
             * 60.1s with the handler and 0.06s without, a 1000x penalty
             * paid entirely on the expected outcome.  RLIMIT_CORE does not
             * suppress a pipe handler; PR_SET_DUMPABLE does, and the
             * signal the parent reads is identical either way.  Both are
             * set: the rlimit for a host that writes core FILES, the
             * dumpable flag for one that pipes. */
            struct rlimit rl = { 0, 0 };
            int devnull;

            setrlimit(RLIMIT_CORE, &rl);
            prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
            /* The verdict comes from waitpid, never from what the child
             * says.  Under qemu-user a fatal guest signal also makes the
             * EMULATOR print a line, and the caller counts the lines on
             * its stderr to learn which CPUID flags TCG refused -- so the
             * child's streams are closed off rather than allowed to
             * contribute thousands of lines to someone else's tally. */
            devnull = open("/dev/null", O_RDWR);
            if (devnull >= 0) {
                dup2(devnull, 1);
                dup2(devnull, 2);
                if (devnull > 2) {
                    close(devnull);
                }
            }
            alarm(VICTIM_SECONDS);
            /* RAX points at writable scratch so a memory operand whose
             * base is r/m=000 addresses something mapped: a SIGSEGV
             * would otherwise be read as a refusal.  RSP and RBP point
             * into the trampoline stack, so an encoding that returns or
             * unwinds leaves through reach_exit_trampoline rather than
             * through this harness's own frames. */
            __asm__ volatile("mov %[scr], %%rax\n\t"
                             "mov %[stk], %%rsp\n\t"
                             "mov %%rsp, %%rbp\n\t"
                             "call *%[pg]\n\t"
                             "jmp reach_exit_trampoline\n\t"
                             :: [scr]"r"(scratch),
                                [stk]"r"(&vstack[VSTACK_SLOTS / 2]),
                                [pg]"r"(page)
                             : "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                               "memory");
            __builtin_unreachable();
        } else {
            int st = 0;
            if (waitpid(pid, &st, 0) != pid) {
                fprintf(stderr, "reach_probe: waitpid failed at encoding "
                        "%lu\n", population);
                return 2;
            }
            if (WIFSIGNALED(st)) {
                caught = WTERMSIG(st);
            } else if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
                caught = -1;
            }
        }
        line[strcspn(line, "\r\n")] = '\0';
        printf("%s\t%s\t%d\n", line, caught ? "no" : "yes", caught);
        emitted++;
        fflush(stdout);
    }

    /* A PROBE THAT EMITTED FEWER ROWS THAN IT READ IS NOT A MEASUREMENT.
     * Nothing in the loop above can reach this with a shortfall today --
     * that is the point of the fork -- but 250-G was exactly a probe
     * whose population and output had silently parted company, and the
     * cost of noticing is one comparison. */
    if (fflush(stdout) != 0 || ferror(stdout)) {
        fprintf(stderr, "reach_probe: stdout write failed after %lu of %lu "
                "encodings\n", emitted, population);
        return 3;
    }
    if (emitted != population) {
        fprintf(stderr, "reach_probe REFUSING: read %lu encodings and wrote "
                "%lu rows, a shortfall of %lu.  Every encoding read must "
                "carry a verdict; a short table is not a measurement of "
                "the machine.\n",
                population, emitted, population - emitted);
        return 4;
    }
    return 0;
}
