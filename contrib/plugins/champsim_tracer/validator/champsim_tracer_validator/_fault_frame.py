"""Fault-frame identity witness (system mode, x86_64): ``fault_frame_test``.

The PathBuilder's fault ledger is per vCPU, and a vCPU multiplexes guest
threads.  Two threads of one process running the same code fault at the same
instruction routinely -- each touching its own not-yet-present page through
its own base register -- and while the first blocks in its handler the guest
scheduler runs the second.  Each fault is an excursion of its own: its own
executed prefix on the wire at the fault, its handler at depth 1, its own
continuation of the block's template.  This cell makes that happen
deterministically and asserts it.

The mechanism is userfaultfd: a resolver thread holds every faulting thread
blocked in ``handle_userfault`` until it chooses to resolve that thread's page
(``UFFDIO_COPY``), so the order of faults and returns is the program's, not
the scheduler's.  The guest runs ``-smp 1`` so both threads share the one
vCPU (and so the one ledger).  Every page the workload owns is populated and
locked before the marker opens the window, so the only faults inside it are
the ones each case schedules, and ``census frames opened`` has an exact
expected value.

The same block also carries the single-thread shapes that must NOT join a
pending frame (an invocation abandoned by a SIGSEGV handler's siglongjmp,
then the block entered afresh) and the one that MUST (two faults in one
invocation: the case-(a2) join).

Rows (each fails when its subject is absent):
  * census_frames_opened == faulting invocations (must be equal),
  * the per-thread body pieces equal the case's expected (bb_start, bb_stop)
    sequences, every piece on the block's one template,
  * between a fault prefix and its continuation the owning thread runs only
    kernel entries, all at fault depth >= 1,
  * and, through the shared system-cell gates: clock_minus_wire == 0, every
    (must be 0) row zero, the guest console clean.

x86_64 only: the guest kernels staged for aarch64, riscv64 and mipsel are
built without CONFIG_USERFAULTFD (systest/build/kbuild/*/.config), while the
x86_64 guest is a distribution kernel that has it.

Author: Maccoy Merrell.  SPDX-License-Identifier: GPL-2.0-or-later
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

ISAS = ("x86_64",)

WITNESS_C = r"""/*
 * Fault-frame ledger witness (x86_64 system mode, -smp 1).
 *
 * One shared block `body` (no branch before its ret):
 *   [0..4]  five ALU instructions
 *   [5]  P  mov (%rdi),%rdx     load through the per-call base p1  (K   = 5)
 *   [6..7]  two ALU
 *   [8]  Q  mov (%rsi),%r8      load through the per-call base p2  (K_Q = 8)
 *   [9]     ALU
 *   [10] R  mov %rax,(%rdi)     store through p1                   (K_R = 10)
 *   [11]    ALU
 *   [12]    ret
 *
 * Every page the process owns is populated and locked before the window
 * opens (threads pre-created, mlockall(MCL_CURRENT)); the only memory
 * mapped afterwards is the witness region.  So the faults inside the window
 * are exactly the ones each mode schedules:
 *
 * MODE 0  negative control: A faults at P (userfaultfd), is resolved, runs
 *         body to its end; only then does B start body and fault at P.
 *         2 excursions, 2 invocations.
 * MODE 1  scenario 1: A faults at P and blocks in handle_userfault; once the
 *         resolver holds A's fault message B starts body and faults at P
 *         too.  With both blocked, A is resolved, the resolver waits for A
 *         to finish body, then resolves B.
 * MODE 4  scenario 1 with B (the second faulter) resolved FIRST.
 * MODE 2  scenario 2: A faults at P; B's P page is present and B faults at
 *         Q.  Same resolution order as MODE 1.
 * MODE 3  single thread: body faults at P on a PROT_NONE page; the SIGSEGV
 *         handler siglongjmps out (that invocation never resumes); body
 *         then runs again with p1 present and p2 a userfaultfd page.
 * MODE 5  as MODE 3, but the second invocation faults at P again.
 * MODE 6  single thread, one invocation, two faults in one block: P reads a
 *         fresh anonymous page (zero-page fault), R writes it (CoW fault).
 *         The second fault rides the first's resume suffix (case a2).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MODE
#error MODE
#endif
#define SINGLE (MODE == 3 || MODE == 5 || MODE == 6)

extern long body(long *p1, long *p2);
__asm__(
    ".text\n"
    ".globl body\n"
    ".type body,@function\n"
    ".p2align 6\n"
    "body:\n"
    "  mov %rdi,%rax\n"
    "  add $1,%rax\n"
    "  xor %ecx,%ecx\n"
    "  add $2,%rcx\n"
    "  imul $3,%rcx,%rcx\n"
    "body_P:\n"
    "  mov (%rdi),%rdx\n"
    "  add %rdx,%rax\n"
    "  add $5,%rcx\n"
    "body_Q:\n"
    "  mov (%rsi),%r8\n"
    "  add %r8,%rax\n"
    "body_R:\n"
    "  mov %rax,(%rdi)\n"
    "  add %rcx,%rax\n"
    "  ret\n"
    ".size body,.-body\n");

__attribute__((noinline)) static void start_marker(void)
{
    __asm__ volatile(
        "  leaq cst_start_marker(%%rip), %%rdi\n"
        "  andq $-4096, %%rdi\n"
        "  movq $8192, %%rsi\n"
        "  movq $149, %%rax\n"
        "  syscall\n"
        "cst_start_marker:\n"
        "  mov $0x43535401, %%eax\n"
        "  mov $0x43535401, %%eax\n"
        "  mov $0x43535401, %%eax\n"
        ::: "rax", "rdi", "rsi", "rcx", "r11", "memory");
}

__attribute__((noinline)) static void end_marker(void)
{
    __asm__ volatile(
        "  mov $0x43535402, %%eax\n"
        "  mov $0x43535402, %%eax\n"
        "  mov $0x43535402, %%eax\n"
        ::: "rax", "memory");
}

#define PG 4096
static long uffd = -1;
static char *region;           /* witness pages, mapped after mlockall */
static char srcpage[PG] __attribute__((aligned(PG)));
static int go[3][2];           /* 0: A, 1: B, 2: resolver */
static int done_pipe[2][2];    /* per worker: written after body */
static volatile long sink[2];

static char *pg(int i) { return region + (size_t)i * PG; }

static void die(const char *m) { perror(m); _exit(2); }

static void put(int fd) { if (write(fd, "x", 1) != 1) die("write"); }

static void take(int fd)
{
    char c;
    while (read(fd, &c, 1) != 1) {
    }
}

static void uffd_register(char *p)
{
    struct uffdio_register r;
    memset(&r, 0, sizeof r);
    r.range.start = (uintptr_t)p;
    r.range.len = PG;
    r.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl((int)uffd, UFFDIO_REGISTER, &r) < 0) {
        die("UFFDIO_REGISTER");
    }
}

static void uffd_resolve(uintptr_t addr)
{
    struct uffdio_copy c;
    memset(&c, 0, sizeof c);
    c.dst = addr & ~(uintptr_t)(PG - 1);
    c.src = (uintptr_t)srcpage;
    c.len = PG;
    if (ioctl((int)uffd, UFFDIO_COPY, &c) < 0) {
        die("UFFDIO_COPY");
    }
}

static uintptr_t uffd_read_fault(void)
{
    struct uffd_msg m;
    for (;;) {
        ssize_t n = read((int)uffd, &m, sizeof m);
        if (n == (ssize_t)sizeof m && m.event == UFFD_EVENT_PAGEFAULT) {
            return (uintptr_t)m.arg.pagefault.address;
        }
        if (n < 0 && errno != EINTR && errno != EAGAIN) {
            die("read uffd");
        }
    }
}

#if !SINGLE
/* page -> worker that faults on it (pages 0,2 are A's; 1,3 are B's) */
static int owner_of(uintptr_t a)
{
    uintptr_t p = a & ~(uintptr_t)(PG - 1);
    return (p == (uintptr_t)pg(0) || p == (uintptr_t)pg(2)) ? 0 : 1;
}

static void *resolver(void *arg)
{
    (void)arg;
    take(go[2][0]);
    put(go[0][1]);                        /* A starts */
    uintptr_t a0 = uffd_read_fault();     /* A is blocked in its handler */
#if MODE == 0
    uffd_resolve(a0);
    take(done_pipe[owner_of(a0)][0]);     /* A returned and finished body */
    put(go[1][1]);                        /* only now does B start */
    uintptr_t a1 = uffd_read_fault();
    uffd_resolve(a1);
    take(done_pipe[owner_of(a1)][0]);
#else
    put(go[1][1]);                        /* B starts while A is blocked */
    uintptr_t a1 = uffd_read_fault();     /* both excursions open */
#if MODE == 4
    uintptr_t t = a0; a0 = a1; a1 = t;    /* resolve the second faulter first */
#endif
    uffd_resolve(a0);
    take(done_pipe[owner_of(a0)][0]);
    uffd_resolve(a1);
    take(done_pipe[owner_of(a1)][0]);
#endif
    return NULL;
}

static void *worker(void *arg)
{
    int w = (int)(intptr_t)arg;
    take(go[w][0]);
#if MODE == 2
    long *p1 = (long *)pg(w == 0 ? 0 : 1), *p2 = (long *)pg(w == 0 ? 2 : 3);
#else
    long *p1 = (long *)pg(w), *p2 = (long *)pg(2 + w);
#endif
    sink[w] = body(p1, p2);
    put(done_pipe[w][1]);
    return NULL;
}
#else
static sigjmp_buf jb;
static void on_segv(int s)
{
    (void)s;
    siglongjmp(jb, 1);
}

static void *resolver1(void *arg)
{
    (void)arg;
    take(go[2][0]);
#if MODE != 6
    uffd_resolve(uffd_read_fault());
#endif
    return NULL;
}
#endif

int main(void)
{
    for (int i = 0; i < 3; i++) {
        if (pipe(go[i]) < 0) {
            die("pipe");
        }
    }
    for (int i = 0; i < 2; i++) {
        if (pipe(done_pipe[i]) < 0) {
            die("pipe");
        }
    }
    memset(srcpage, 0x11, PG);
    uffd = syscall(SYS_userfaultfd, O_CLOEXEC);
    if (uffd < 0) {
        die("userfaultfd");
    }
    struct uffdio_api api = { .api = UFFD_API, .features = 0 };
    if (ioctl((int)uffd, UFFDIO_API, &api) < 0) {
        die("UFFDIO_API");
    }
    pthread_t r;
#if !SINGLE
    pthread_t a, b;
    pthread_create(&r, NULL, resolver, NULL);
    pthread_create(&a, NULL, worker, (void *)(intptr_t)0);
    pthread_create(&b, NULL, worker, (void *)(intptr_t)1);
#else
    pthread_create(&r, NULL, resolver1, NULL);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_segv;
    sigaction(SIGSEGV, &sa, NULL);
    sigjmp_buf warm;                      /* touch the sigsetjmp path once */
    (void)sigsetjmp(warm, 1);
#endif
    if (mlockall(MCL_CURRENT) < 0) {
        die("mlockall");
    }
    region = mmap(NULL, 5 * PG, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        die("mmap");
    }
#if !SINGLE
#if MODE == 2
    *(volatile long *)pg(1) = 1;          /* B's P page present */
    *(volatile long *)pg(2) = 1;          /* A's Q page present */
    uffd_register(pg(0));
    uffd_register(pg(3));
#else
    *(volatile long *)pg(2) = 1;          /* both Q pages present */
    *(volatile long *)pg(3) = 1;
    uffd_register(pg(0));
    uffd_register(pg(1));
#endif
    start_marker();
    put(go[2][1]);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    pthread_join(r, NULL);
#else
    char *bad = mmap(NULL, PG, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (bad == MAP_FAILED) {
        die("mmap bad");
    }
    *(volatile long *)pg(0) = 1;
    *(volatile long *)pg(2) = 1;
#if MODE == 3
    uffd_register(pg(3));
#elif MODE == 5
    uffd_register(pg(1));
#endif
    start_marker();
    put(go[2][1]);
#if MODE == 6
    sink[0] = body((long *)pg(4), (long *)pg(4)); /* zero-page at P, CoW at R */
#else
    if (sigsetjmp(jb, 1) == 0) {
        sink[0] = body((long *)bad, (long *)pg(2));   /* SIGSEGV at P */
    }
#if MODE == 3
    sink[1] = body((long *)pg(0), (long *)pg(3));     /* uffd fault at Q */
#else
    sink[1] = body((long *)pg(1), (long *)pg(2));     /* uffd fault at P */
#endif
#endif
    pthread_join(r, NULL);
#endif
    end_marker();
    fprintf(stderr, "uffd_witness: mode %d sink %ld %ld\n", MODE,
            sink[0], sink[1]);
    return 0;
}
"""


# The workload's one block, by instruction index (see the C source).
BODY_N = 13
K_P, K_Q, K_R = 5, 8, 10

# Kernel text on the x86_64 guest (canonical upper half).
_KERNEL_PC = 0xffff800000000000


@dataclass(frozen=True)
class Case:
    """One witness shape.

    @frames is the number of fault frames the run must open: one per body
    invocation that faulted, since every faulting invocation is its own
    excursion identity (a second fault inside the SAME invocation joins
    it).  No other fault can occur inside the window — the workload
    populates and locks everything it owns before the marker — so the
    census row has an exact subject.  @pieces is the multiset of per-thread
    body piece sequences the wire must carry, as (bb_start, bb_stop)."""
    name: str
    mode: int
    frames: int
    pieces: tuple
    what: str


CASES = (
    Case("serial", 0, 2,
         (((0, K_P), (K_P, BODY_N)), ((0, K_P), (K_P, BODY_N))),
         "negative control: B faults at P only after A's excursion returned "
         "and A finished the block"),
    Case("peer_same_pc", 1, 2,
         (((0, K_P), (K_P, BODY_N)), ((0, K_P), (K_P, BODY_N))),
         "A blocks in its fault at P; B runs the block and faults at P too; "
         "A is resolved first"),
    Case("peer_same_pc_bfirst", 4, 2,
         (((0, K_P), (K_P, BODY_N)), ((0, K_P), (K_P, BODY_N))),
         "as peer_same_pc, B resolved (and returned) first"),
    Case("peer_later_pc", 2, 2,
         (((0, K_P), (K_P, BODY_N)), ((0, K_Q), (K_Q, BODY_N))),
         "A blocks in its fault at P; B (P page present) faults at the "
         "later Q of the same block"),
    Case("abandoned_later_pc", 3, 2,
         (((0, K_P), (0, K_Q), (K_Q, BODY_N)),),
         "one thread: a SIGSEGV at P siglongjmps out of the block; a new "
         "invocation then faults at Q"),
    Case("abandoned_same_pc", 5, 2,
         (((0, K_P), (0, K_P), (K_P, BODY_N)),),
         "one thread: a SIGSEGV at P siglongjmps out of the block; a new "
         "invocation then faults at P"),
    Case("join", 6, 1,
         (((0, K_P), (K_P, K_R), (K_R, BODY_N)),),
         "one thread, one invocation, two faults in one block: zero-page "
         "read at P, CoW write at R (the case-a2 join)"),
)
CASE_BY_NAME = {c.name: c for c in CASES}


def build(case: Case, out_dir: Path) -> Path:
    """Compile @case's workload (static: the guest root is a busybox tree)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    src = out_dir / "fault_frame_witness.c"
    src.write_text(WITNESS_C)
    exe = out_dir / f"fault_frame_{case.name}"
    cmd = ["gcc", "-std=gnu11", "-O1", "-static", "-pthread",
           f"-DMODE={case.mode}", str(src), "-o", str(exe)]
    if subprocess.call(cmd) != 0:
        raise RuntimeError(f"fault_frame[{case.name}]: {' '.join(cmd)} failed")
    return exe


def body_extent(exe: Path) -> tuple:
    """[lo, hi) of the `body` block, from the symbol table."""
    out = subprocess.run(["nm", "-S", str(exe)], capture_output=True,
                         text=True, check=True).stdout
    for line in out.splitlines():
        f = line.split()
        if len(f) == 4 and f[3] == "body":
            lo = int(f[0], 16)
            return lo, lo + int(f[1], 16)
    raise RuntimeError(f"{exe}: no sized `body` symbol")


_BB = re.compile(r"^BB(\d+) \[pc=0x([0-9a-f]+), insns=(\d+)")
_ENT = re.compile(r"^ENTRY \S+ thread=(\d+) .*?template=BB(\d+)")
_RNG = re.compile(r"range=(\d+)\.\.(\d+)")
_DEP = re.compile(r"fault_depth=(\d+)")


@dataclass
class _Strand:
    pieces: list = field(default_factory=list)  # (tmpl, lo, hi)
    # Per gap after each piece: kernel-entry depths, and user entries seen.
    gap_depths: list = field(default_factory=list)
    gap_user: list = field(default_factory=list)


def scan_wire(cst: Path, decoder: Path, lo: int, hi: int) -> dict:
    """Stream the trace's legacy decode once and return, per thread, the
    body pieces and what ran between consecutive pieces.  Bounded: one
    pass, only the body's pieces and per-gap depth tallies are kept."""
    tmpl = {}
    strands: dict = {}
    proc = subprocess.Popen([str(decoder), "--format=legacy", str(cst)],
                            stdout=subprocess.PIPE, text=True,
                            errors="replace")
    for line in proc.stdout:
        m = _BB.match(line)
        if m:
            tmpl[m.group(1)] = (int(m.group(2), 16), int(m.group(3)))
            continue
        m = _ENT.match(line)
        if not m:
            continue
        tid, t = int(m.group(1)), m.group(2)
        pc, n = tmpl.get(t, (0, 0))
        s = strands.setdefault(tid, _Strand())
        if lo <= pc < hi:
            r = _RNG.search(line)
            a, b = (int(r.group(1)), int(r.group(2))) if r else (0, n)
            s.pieces.append((t, a, b))
            s.gap_depths.append([])
            s.gap_user.append(0)
        elif s.pieces:
            if pc >= _KERNEL_PC:
                d = _DEP.search(line)
                s.gap_depths[-1].append(int(d.group(1)) if d else 0)
            else:
                s.gap_user[-1] += 1
    rc = proc.wait()
    if rc != 0:
        raise RuntimeError(f"cst_decode --format=legacy {cst} rc={rc}")
    return {tid: s for tid, s in strands.items() if s.pieces}


def assess(case: Case, label: str, strands: dict, stats_text: str,
           stats_value) -> int:
    """The cell's rows.  Each names its subject and fails when the subject
    is absent; returns 0 when every row holds."""
    rc = 0
    if "census frames opened" not in stats_text:
        print(f"{label}: FAIL  the stats log carries no 'census frames "
              f"opened' row -- the frame census cannot be read")
        return 1
    opened = stats_value(stats_text, "census frames opened")
    ok = opened == case.frames
    print(f"{label}: census_frames_opened={opened} "
          f"faulting_invocations={case.frames} (must be equal)  "
          f"{'ok' if ok else 'FAIL'}")
    rc |= 0 if ok else 1

    if not strands:
        print(f"{label}: FAIL  no body piece on the wire -- the cell's "
              f"subject is absent")
        return 1
    got = sorted(tuple((a, b) for _t, a, b in s.pieces)
                 for s in strands.values())
    want = sorted(case.pieces)
    ok = got == want
    print(f"{label}: body pieces per thread {got}  expected {want}  "
          f"{'ok' if ok else 'FAIL'}")
    rc |= 0 if ok else 1

    ids = {t for s in strands.values() for t, _a, _b in s.pieces}
    ok = len(ids) == 1
    print(f"{label}: body template ids {sorted(ids)} (must be one: every "
          f"piece names the block's own template)  {'ok' if ok else 'FAIL'}")
    rc |= 0 if ok else 1

    # The excursion between a fault prefix and its continuation is the
    # owning thread's handler: every kernel entry of that thread in the gap
    # runs at fault depth >= 1, and the thread runs no user code there.
    for tid, s in sorted(strands.items()):
        for i in range(len(s.pieces) - 1):
            _t, a, b = s.pieces[i]
            _t2, a2, _b2 = s.pieces[i + 1]
            if b >= BODY_N or a2 != b:
                continue                    # not one invocation's two halves
            deps = s.gap_depths[i]
            shallow = sum(1 for d in deps if d < 1)
            ok = bool(deps) and shallow == 0 and s.gap_user[i] == 0
            print(f"{label}: thread {tid} excursion after [{a},{b}): "
                  f"kernel entries={len(deps)} at depth 0={shallow} "
                  f"user entries={s.gap_user[i]} (must be >0, 0, 0)  "
                  f"{'ok' if ok else 'FAIL'}")
            rc |= 0 if ok else 1
    return rc
