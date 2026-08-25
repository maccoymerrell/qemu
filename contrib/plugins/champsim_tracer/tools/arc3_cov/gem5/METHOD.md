# ARC 3 -- the aarch64 and mipsel EXECUTION leg, against gem5

Author: Maccoy Merrell.

## Why this exists

`EXEC_VERDICT.md` §2 tabulates, per ISA and per facet, whether a number was
validated against a real run.  Ten of its twenty-four cells read `NONE`, and
**eight of those ten are on aarch64 and mipsel**.  Every earlier number on
those two ISAs came from one of two places, and neither can close such a cell:

* a **static** decoder -- Arm's Machine Readable Architecture, binutils
  `mips-opc`, LLVM MC.  A static decoder has no address and no value to give.
* **`irdf`**, which compares the tracer's static claim against QEMU's own TCG
  translation.  Both sides are QEMU, so a green `irdf` arm is evidence about an
  internal inconsistency and about nothing else.

gem5 is neither.  It has its own decoder and its own execution semantics for
both AArch64 and MIPS, and in syscall-emulation mode it runs the SAME static
ELF the tracer traces.  That makes a 1-to-1 comparison possible on the facets
a static reference cannot reach: **memop address, memop width, memop data and
register values**.

## Shape of the comparison

    guest ELF ──> gem5.opt --debug-flags=Exec…  ──> exec.log ──┐
              └─> qemu-<isa> + libchampsim_tracer.so ──> .cst ─┴─> compare

`compare_exec_gem5.py` aligns the two instruction streams on `(pc, encoding)`
-- the encoding read out of the ELF, since gem5's log does not print it -- and
scores nine axes:

    reg-dst-set   reg-dst-value   flags-dst-set   fpsr-dst-set
    memop-count   memop-addr      memop-width     store-data    load-data

Every disagreeing row carries a DIRECTION (measured from the two sets, never
read off a label) and a CATEGORY (a named mechanism), through the shared
`arc3_taxonomy`.  "N disagree" is never the result.

## Why the probes look the way they do

gem5's SE-mode process loader and qemu-user lay out the stack, the auxiliary
vector and the environment differently, so any address derived from SP differs
between the two runs for reasons that have nothing to do with either tool.  An
address derived from a link-time symbol does not.  Every probe is therefore a
static `-nostdlib` non-PIE ELF that works out of a fixed-address `.data`
arena and never touches the stack.  That is what makes `memop-addr` an
exact-equality axis rather than a delta model.

The vocabulary is chosen against the OPEN rows of `EXEC_VERDICT.md`, not for
breadth: `ld2`/`ld3`/`ld4`, `ldp`/`stp`, `ld1`--`st4`, the exclusive and LSE
atomics, and the prefetch/cache hints are all there in strength because that
is where the unaccounted rows are.

## What gem5 had to be taught (`gem5.patch`)

Stock gem5 prints, per micro-op, the PC, the disassembly, the OpClass, one
data word `D=` and an effective address `A=`.  Four things a 1-to-1
comparison needs are missing, and the patch adds them:

| addition | why the stock trace cannot serve |
|---|---|
| `S=` / `MF=` — access width and request flags | without a width an address comparison cannot say how many bytes moved |
| `RW=[cls:idx=0x…]` — EVERY destination written, with its value | `D=` is a single word owned by whichever destination wrote last.  Pairing it with the first destination, or with the last, is right some of the time; its errors read as tracer defects.  Measured: `ldp_uop x0, x1` prints one `D=`, and it is x1's |
| `MD=` — the bytes a store moved | a store has no destination register, so `D=` is never set for one and the stored value never reaches the log |
| direction | the OpClass cannot carry it: a read-modify-write micro-op has ONE OpClass and performs BOTH halves.  Direction is taken from the `IsAtomic`/`IsStore`/`IsLoad` instruction flags |

The sidecar (`src/cpu/arc3_trace.hh`) is a plain global rather than a member of
`InstRecord`, so that adding it rebuilds a handful of files instead of the
whole tree.  That is sound only for a CPU model that runs one instruction at a
time to completion, which is what this leg uses (`AtomicSimpleCPU`); an
out-of-order model would interleave writers into it.

The patch also carries one genuine **upstream gem5 bug fix**, not a harness
convenience: `src/arch/mips/isa/formats/fp.isa` asserted `sizeof(T) == 4` in
`fpNanOperands` and `fpInvalidOp`, so every double-precision MIPS FP
instruction aborted the simulator outright
(``Assertion `sizeof(T) == 4' failed``).  The bodies were already parameterised
on `T` everywhere except the NaN width and the QNaN constant; both now come
from `T`.

## Reference limitations, measured and named

These are things gem5 cannot do, found by running it.  They bound what this
leg covers and they are stated rather than absorbed:

* **AArch64 cache maintenance USED TO abort gem5, and the cause was gem5's
  SE-mode reset value, not the instructions.**  `dc cvau` ended in
  `src/sim/faults.cc:103: panic: … Page table fault when accessing virtual
  address 0x400`, and that 0x400 is not an address the program ever names --
  it is `VBAR_EL1` (0 in SE mode) plus 0x400, the synchronous-exception-from-
  a-lower-EL vector offset.  The instruction was TRAPPING.
  `ISA::initializeMiscRegMetadata()` builds the SCTLR reset value in two
  branches and sets `uci` and `dze` on the AArch32 one only, so under AArch64
  every EL0 execution of DC CVAU / DC CVAC / DC CIVAC / IC IVAU fails
  `checkFaultAccessAArch64SysReg`'s `!sctlr.uci` test.  Linux sets both bits
  at boot, which is why the same static ELF runs fine under QEMU linux-user.
  Fixed in `gem5.patch` (two lines), and `probes/p_cache` is now IN the run
  set: measured per operation, `dc cvau` / `dc civac` / `dc cvac` /
  `ic ivau` / `dc zva` all run to
  `Exiting @ tick 3500 because exiting with last active thread context`,
  where before the patch the first four aborted on signal 6 having logged
  three instructions.  Evidence `cst_runs/p3/arc3/item789/gem5cache*/`.

  What gem5 gives on the axis, now that it runs: `dc cvau, x21` logs
  `A=0x410480 S=64` -- a line-aligned effective address and the cache-line
  width, modelled as an `IsStore` with `Request::CLEAN` -- while `ic ivau`
  is modelled as a plain `msr ic_ivau_xt, x21` and issues no request at all.
  So the reference is a THIRD opinion on the direction question mipsel
  `synci` raised: binutils says store, LLVM and QEMU say neither, gem5 says
  store.  The one TRACER-SUBSET row it exposes is `memop-width`: the
  synthetic-EA record carries width 0 where gem5 carries 64.

* **`dc ivac` and `dc cvap` are still unimplemented in gem5** --
  `panic: Attempted to execute unimplemented instruction 'dc ivac'` and, for
  DC CVAP, `'msr'`.  Both are outside the EL0-visible set the UCI bit gates,
  so they are out of `p_cache` rather than patched around.
* **EL1 system registers abort gem5.**  `mrs x0, midr_el1` ->
  `src/arch/arm/faults.cc:787: panic: Attempted to execute unimplemented
  instruction 'mrs'`.  The EL0-visible ID registers (`ctr_el0`, `dczid_el0`,
  `tpidr_el0`, `cntvct_el0`) do run.
* **MIPS single<->double FP conversion aborts gem5.**
  `src/arch/mips/utility.cc:88: panic: Invalid Floating Point Conversion Type
  (3)`.  `cvt.d.s` / `cvt.s.d` are out of the mipsel probe.
* **MIPS `pref`/`prefe`/`synci` are unimplemented in gem5** ("Prefetching not
  implemented for MIPS", "instruction 'synci' unimplemented"), so the
  reference issues no access for them at all.
* **gem5's transcribed `miscRegName[]` cannot be read positionally.**  Read
  out of the header, index 819 resolves to `icv_iar0_el1`; gem5's own
  disassembly of the instruction that writes index 819 says
  `msr tpidr_el0, x3`.  The harness therefore LEARNS the map from every
  `mrs`/`msr` line, the learned answer wins, and each conflict with the table
  is counted and printed.  A silent wrong name would put a register in the
  wrong tracer family and read as agreement.
* **gem5 MIPS never publishes HI/LO writes** to its instruction trace, so
  `mult`, `div`, `madd`, `mthi`, `mtlo` report no destination there.

## The interpreter gem5 is built against, and the SIGSEGV that is not a bug

`gem5.opt` embeds CPython.  On this host it carries

    DT_NEEDED  libpython3.11.so.1.0
    RUNPATH    (none)

and the system interpreter is 3.12, so that library exists only inside the
Anaconda installation scons found: the build log records `Using Python config:
python3-config` / `Checking Python version... 3.11.5`, and `python3-config` on
PATH resolves to `/home/maccoy-merrell/anaconda3/bin/python3.11-config`.  With
no RUNPATH the loader cannot find it on its own, and the leg does not run.

**The obvious remedy makes gem5 SEGFAULT, and that is worth writing down
because it looks exactly like a broken gem5.**  Put the whole Anaconda `lib`
on `LD_LIBRARY_PATH` and gem5 links, starts, runs its embedded interpreter,
imports `m5`, builds SimObjects — and dies at the *first* `cprintf` to
`std::cout`.  Observed under gdb:

    Program received signal SIGSEGV
    #0  gem5::cp::Print::Print (...)     at src/base/cprintf.cc:55
        55     savedFlags = stream.flags();
    #1  gem5::ccprintf<unsigned long>    at src/base/cprintf.hh:148
    #3  gem5::fixClockFrequency ()       at src/sim/core.cc:108

Anaconda ships `libstdc++.so.6` at `GLIBCXX_3.4.29`; the system one this gem5
was compiled against is `GLIBCXX_3.4.33`.  gem5's own `verneed` asks for no
more than `GLIBCXX_3.4.29`, so **nothing is missing and the loader is
satisfied** — the failure is at run time, in the `std::ostream` state of a
`std::cout` supplied by a library that is not the one gem5's translation units
were built with.  Isolated one library at a time, with only `libpython` plus
one candidate exposed:

| exposed alongside libpython | gem5 exit |
|---|---|
| `libstdc++.so.6` | **139 (SIGSEGV)** — the cause, alone sufficient |
| `libgcc_s.so.1` | 0 |
| `libz.so.1` | 0 |

So the interpreter is exposed through a **shim directory holding exactly one
symlink** — the `libpython` soname gem5 asked for, and nothing else.  Every
other library keeps resolving the way it did at link time.  `gem5_env.py`
builds that shim, and it also *strips* from any inherited `LD_LIBRARY_PATH`
every directory that supplies one of `gem5_env.ABI_LIBS`, naming each removal
in `PREREQ.txt`.  The failure above cannot be reached by accident any more.

## Prerequisites, and what happens when one is absent

`compare_exec_gem5.py` resolves every prerequisite before it runs a single
guest, and **exits 3 with a named absence** rather than handing the caller a
signal.  A reference that dies on SIGSEGV leaves a facet cell reading `CITED`
forever; a reference that says what it needs can be fixed in one step.

| absence | what the harness does |
|---|---|
| `libpython<v>.so.1.0` not findable | names the soname, lists every directory searched, points at `--python-home` / `CST_GEM5_PYLIB` |
| `build/<TARGET>/gem5.opt` not built | names the target and the `scons` line that builds it |
| gem5 links but cannot run | runs `startproof.py` (below) and reports the signal with the `cprintf.cc:55` diagnosis |
| no `gem5_ref.REGMAP` entry for the ISA | names the ISA and the function to add, instead of scoring unmapped registers as agreement |
| gem5 exits non-zero, or exits 0 without `Exiting @ tick … because exiting with last active thread context`, or writes an empty `exec.log` | **refuses to score anything** — a truncated reference stream would read as tracer superset |

`startproof.py` is why the third row works.  `gem5.opt --help` returns 0 under
the broken loader path — measured — so a preflight built on it is **inert**.
The start proof calls `m5.instantiate()`, which is what reaches
`fixClockFrequency`, the frame the fault actually occupies.

All five refusals were watched firing, deliberately, with the prerequisite
removed:

    control 1  run under /usr/bin/python3 (3.12), no CST_GEM5_PYLIB
               -> rc=3, "MISSING PREREQUISITE: libpython3.11.so.1.0"
    control 2  GEM5_BUILD pointed at an unbuilt RISCV target
               -> "MISSING PREREQUISITE: gem5.opt for the RISCV target"
    control 3  LD_LIBRARY_PATH=<anaconda>/lib, the poisoned path
               -> sanitiser drops it, names the drop, gem5 starts
    control 4  same, with gem5_env.ABI_LIBS emptied so the poison survives
               -> "PREREQUISITE UNMET: ... start proof died on signal 11"
    control 5  a REAL truncated run (se.py -I 5, gem5 exit 0)
               -> "gem5 stopped ... for a reason that is NOT the guest
                   reaching its own end: a thread reached the max
                   instruction count.  Nothing is scored."

Control 4 matters most: before the start proof was deepened it did **not**
fire, and the check was inert.  That is the whole reason it is an
`m5.instantiate()` script and not `--help`.

## Building gem5

Built with the same Anaconda interpreter that will run it, and with the shim
already in place so scons' own `Python.h` conftest can link:

    export PATH=/home/maccoy-merrell/anaconda3/bin:$PATH
    mkdir -p /mnt/md0/QEMU/cst_runs/p3/arc3/gem5fix/pylib
    ln -sf /home/maccoy-merrell/anaconda3/lib/libpython3.11.so.1.0 \
           /mnt/md0/QEMU/cst_runs/p3/arc3/gem5fix/pylib/
    export LD_LIBRARY_PATH=/mnt/md0/QEMU/cst_runs/p3/arc3/gem5fix/pylib

    git clone --depth 1 https://github.com/gem5/gem5 && cd gem5
    git apply /path/to/arc3_cov/gem5/gem5.patch
    scons build/ARM/gem5.opt build/MIPS/gem5.opt build/X86/gem5.opt -j 64

Without that `LD_LIBRARY_PATH` the *build* fails too, and misleadingly:

    Checking Python version... conftest_...: error while loading shared
    libraries: libpython3.11.so.1.0: cannot open shared object file
    Error: Can't find a working Python installation

Targets built at gem5 `62c7bf2` (v25.1.0.1) with the patch applied:

| target | binary | status |
|---|---|---|
| `ARM` | `build/ARM/gem5.opt` | runs the aarch64 probe set to completion |
| `MIPS` | `build/MIPS/gem5.opt` | runs the mipsel probe set to completion |
| `X86` | `build/X86/gem5.opt` | runs a static glibc workload to completion |

The X86 check was a real program, not a smoke test — `gcc -O2 -static`, a
10,000-iteration loop, `printf`:

    build/X86/gem5.opt -d <out> configs/deprecated/example/se.py \
        --cpu-type=AtomicSimpleCPU -c hello_x86
    sum=333283335000
    Exiting @ tick 211059000 because exiting with last active thread context

**X86 is built and proven to run; it is not yet scoreable.**
`gem5_ref.REGMAP` has readers for `aarch64` and `mipsel` only, so
`--isa x86_64` refuses by name rather than scoring unmapped registers as
agreement.  Adding an `_x86_reg` reader next to `_arm_reg` / `_mips_reg` is
the one remaining step.

## Running it

    ninja -C /mnt/md0/QEMU/qemu/build contrib-plugins

    # probes, once
    python probes/mkprobes_aarch64.py <outdir>/probes_a64
    python probes/mkprobes_mipsel.py  <outdir>/probes_mipsel

    # the comparison -- no LD_LIBRARY_PATH, no CST_GEM5_PYLIB, no PYTHONHOME.
    # Run under the interpreter gem5 was built against and the harness works
    # the loader path out for itself.
    cd contrib/plugins/champsim_tracer/tools/arc3_cov/gem5
    /home/maccoy-merrell/anaconda3/bin/python compare_exec_gem5.py \
        --isa aarch64 \
        --gem5-dir /mnt/md0/QEMU/cst_runs/p3/arc3/gem5exec/gem5 \
        --qemu-dir /mnt/md0/QEMU/qemu \
        --decode /mnt/md0/QEMU/qemu/build/contrib/plugins/cst_decode \
        -o <outdir>/a64 --tsv <outdir>/a64/rows.tsv \
        <probes_a64>/p_int <probes_a64>/p_mem <probes_a64>/p_simd \
        <probes_a64>/p_atomic <probes_a64>/p_fp <probes_a64>/p_flow \
        <probes_a64>/p_hint <probes_a64>/p_cache

`p_cache` joined the aarch64 set once the gem5 SCTLR reset bug above was
fixed; it was absent for as long as gem5 aborted on it.  The mipsel set is `p_int p_mem p_fp p_flow`.

If the run must happen under a *different* interpreter, pass
`--python-home <prefix>` — the prefix whose `lib/` holds the soname in
`gem5.opt`'s `DT_NEEDED`.  Only that one library is exposed; passing the
prefix does **not** put its `lib/` on the loader path, for the reason above.

Exit codes are the tool's own and must be taken from the process, never
through a pipe:

    0  no TRACER-SUBSET and no UNACCOUNTED row
    1  scored, and the headline is non-zero
    3  REFUSED -- a prerequisite is absent, or gem5 did not run to completion.
       Nothing was scored and no facet cell may be written from the run.

Every decision the harness took about the loader path is written to
`<outdir>/PREREQ.txt`, and gem5's own console output per guest to
`<outdir>/<guest>.gem5.out`.

## Determinism

`rows.tsv` renders sets through `render()` rather than `repr()`.  CPython
randomises `set` iteration order per process, and two byte-identical
measurements previously produced TSVs differing on 24 of 49 aarch64 rows for
no reason but `PYTHONHASHSEED`.  A reference nobody can diff against the last
run is a reference nobody can check.  Verified across `PYTHONHASHSEED=1` and
`PYTHONHASHSEED=12345`: `REPORT.txt` identical, `rows.tsv` identical.

One row is *legitimately* not reproducible, and it is already adjudicated:
`mrs x4, cntvct_el0` in `p_hint` reads the virtual counter, so the tracer
publishes a fresh nanosecond timestamp every run while gem5 publishes 0.  Its
category (`IMPLDEF-MACHINE-VALUE`), direction (`TRACER-SUBSET`) and its
contribution to every headline are constant; only the printed value moves.
