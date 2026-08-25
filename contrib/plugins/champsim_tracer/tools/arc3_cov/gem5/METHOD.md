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

* **AArch64 cache maintenance aborts gem5.**  `dc cvau` in SE mode ends in
  `src/sim/faults.cc:103: panic: … Page table fault when accessing virtual
  address 0x400`.  `probes/p_cache` exists and is deliberately NOT in the run
  set; `EXEC_VERDICT.md` W3 stays on the static axis.
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

## Running it

    ninja -C /mnt/md0/QEMU/qemu/build contrib-plugins

    # gem5, once
    git clone --depth 1 https://github.com/gem5/gem5 && cd gem5
    git apply /path/to/arc3_cov/gem5/gem5.patch
    scons build/ARM/gem5.opt build/MIPS/gem5.opt -j <n>

    # probes
    python probes/mkprobes_aarch64.py <outdir>/probes_a64
    python probes/mkprobes_mipsel.py  <outdir>/probes_mipsel

    # the comparison
    CST_GEM5_PYLIB=<dir holding libpython3.11.so.1.0> \
    python compare_exec_gem5.py --isa aarch64 \
        --gem5-dir <gem5> --qemu-dir /mnt/md0/QEMU/qemu \
        --decode /mnt/md0/QEMU/qemu/build/contrib/plugins/cst_decode \
        -o <outdir>/run_a64 --tsv <outdir>/run_a64/rows.tsv \
        <outdir>/probes_a64/p_*

The exit code is the tool's own: non-zero while TRACER-SUBSET + UNACCOUNTED is
non-zero.  Never take it through a pipe.

gem5 links against the interpreter that built it.  If that is an Anaconda
Python whose `libpython3.11.so.1.0` is not on the default loader path, put a
symlink to it in a directory of its own and name that directory in
`CST_GEM5_PYLIB` -- putting the whole Anaconda `lib` on `LD_LIBRARY_PATH`
also puts its older `libstdc++` in front of the one gem5 was built with.
