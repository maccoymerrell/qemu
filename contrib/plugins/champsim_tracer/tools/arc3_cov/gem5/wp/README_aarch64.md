# aarch64 WRONG-PATH execution cross-check — ChampSim Tracer against gem5

`STATUS.md` and every gate this project runs compare correct path against
correct path.  A wrong-path divergence was invisible for the whole arc on
every ISA until the riscv64 leg against Spike, and the wrong-path arm is a
large fraction of what the tracer emits.  The maintainer's direction for the
rest was:

> "The remaining 3 ISAs can have their wrong-paths verified by gem5."

This is that leg for aarch64.  It mirrors the riscv64 one fact for fact.

```
   trace ──► reconstructed regfile + memory ──► injected static ELF
                                                       │
                                                     gem5
                                                       │
   the tracer's WP record ◄──── compared against ──── what the ISA does
```

## What an excursion is here

The unit is the whole WP **chain** hanging off one CP entry, not one WP block.
`emit_finalized_bb` kicks a single synchronous excursion that runs until the
`wpdepth` budget exhausts; the decoder renders it as `wp[0] wp[1] …` because a
chain is cut into basic blocks, not because each block is an independent
event.  Comparing per block would compare N starting states the tracer never
claimed.

The excursion's starting state is the architectural state at the **end of its
CP entry**: only correct-path effects update it.  A wrong-path write is
discarded by the machine when the excursion ends, so replaying one into the
shadow would seed the next excursion from a state that never existed.

## The reconstruction, and why it is the interesting part

`format.rst` §5.4 says a consumer rebuilds the register file from the REGFILE
seed plus the DST_REG snapshots.  `wp_trace.py` — shared verbatim with the
riscv64 leg, because it reads `cst_decode` output and is ISA-agnostic —
performs exactly that reconstruction; memory is rebuilt from three sources the
wire states: the ELF image, the datum every correct-path **load** returned, and
the datum every correct-path **store** wrote.

| verdict | meaning |
| --- | --- |
| `WP-DEFECT` | the excursion executed something the architecture would not, from a starting state the trace fully specified |
| `RECONSTRUCTION-GAP` | the trace does not carry enough state to rebuild the starting point — a finding about what the **wire** drops |
| `GEM5-LIMIT` | the reference cannot state the fact: it stopped before the excursion did, it panicked on an instruction class, or its own record names something the architecture does not |
| `TRACER-SUPERSET` | we record a fact the reference omits, and a **named** rule says why.  COVERED, not a defect |
| `UNACCOUNTED` | a disagreement nobody has explained.  MUST BE 0 |

The gap verdict is assigned from **evidence, never from plausibility**.  A
register is a gap only where the `wp-entry-state` axis measures the
reconstruction wrong against the correct-path run's own ground truth; an
address is a gap only where no ELF byte, no CP load datum and no CP store
datum ever established it.

## How the state gets into gem5

gem5 has no "set the register file" interface, so the state is installed the
only way a machine accepts state: as instructions.  `wp_seed_a64.py` emits a
static ELF whose entry point materialises every register the trace named with
`movz`/`movk`, `ldr q`, `msr fpcr`, `msr nzcv` and `mov sp`, and then transfers
to the excursion's first PC.

* **The transfer consumes no register.**  It is a direct `B`, whose target is a
  PC-relative immediate.  `x16`/`x17` are the prologue's scratch and are
  therefore written **last**, immediately before the branch.  The reach of
  `B` is ±128 MiB and it is CHECKED, not assumed: a guest linked outside that
  window refuses rather than truncating the offset.
* **The prologue is excluded BY ADDRESS, never by count.**  It lives at
  `0x300000` and the guest at its own link address.  Every segment of the
  injected image is marked executable precisely so gem5's own range filter
  cannot delete a reference instruction the excursion really reached; the
  prologue is then removed by its own range.
* **SE mode, not bare metal.**  gem5 starts a static ELF at `e_entry` in EL0,
  which is the privilege level a qemu-user trace was recorded at — so unlike
  the riscv64 leg nothing about privilege has to be traded away.

Costs, stated rather than hidden:

* SE mode has no page table to populate, so every address the excursion
  touches must be in a `PT_LOAD` of the injected image.  An address the wire
  never established is not there, gem5 raises its SE-mode page fault, and that
  is reported as evidence.
* **`FPSR` has no source on the wire.**  Capstone's aarch64 register space has
  no `FPSR` at all, so the tracer's table cannot name it and no snapshot can
  carry it.  Reported as a seed gap on every excursion.
* **SVE state is not installed.**  The trace's `REG_VEC` values are the full Z
  registers (512 bits under this QEMU's `vg=8`) and the predicate file arrives
  as `REG_PRED0..16`.  The prologue installs the low 128 bits of each Z — the
  architectural V register — and names the Z tail, `p0`–`p15` and `ffr` as
  seed gaps.  Nothing is silently zeroed: a silent zero agrees with the
  reference on every register that happens to be zero and manufactures a pass.

## Why the source axes are partitioned

gem5's `SR=` is a **micro-op** source list, not an architectural read set: it
threads `cpsr` through essentially every instruction and `cpacr_el1` through
every vector one.  The partition is taken on gem5's own register **class**, not
on the mapped id, because `condition_code:0` and `miscellaneous:0` both map to
`REG_FLAGS` while meaning entirely different things — one is a real NZCV read
(exactly the fact R4 says a conditional form must record) and the other is
machine state.

    reg-src-set    the general and vector register FILE
    flags-src-set  the condition-code word, as gem5's own cc registers state it
    sys-src-set    everything gem5 reads out of its misc file

The machine-state exemption is held to **exactly the register measured to
behave that way** — `cpsr` — and to nothing else.  A blanket "the misc file
does not count" would swallow `cpacr_el1` and `fpscr`, which the two tools
already agree on, and with them any future row where the tracer really did
drop a system source.  The negative control watches that: it drops a
`REG_SYSFPEN` source and the axis fires.

## The negative control is part of the result

`selftest_wp_a64.py` breaks one fact on one side of one real aligned pair and
requires the axis that owns it to fire.  **Fifteen** axes plus the injection
control, all firing, is the bar; an axis with no firing mutation reports
`UNPROVEN` and its zero is not counted as a pass.

The **injection control** is the load-bearing one: it perturbs the state that
is *installed* and requires gem5's own execution to change.  Without it, an
agreement could mean the reconstruction is correct, or it could mean the
reconstruction never reached the simulator and the excursion followed the same
path regardless — indistinguishable from the comparison alone.

The control earned its keep immediately.  With `FLAGS-GRANULARITY` and
`FPSR-GRANULARITY` applied by AXIS — the way the correct-path leg applies them
— dropping the tracer's flag destination did **not** fire.  Those labels are
right on the correct-path leg, which compares gem5's sub-field registers
against the tracer's whole word; here both sides have already been mapped onto
GenericRegIds, where gem5's nz/c/v are one `REG_FLAGS`, so the granularity is
gone before the comparison and a disagreement is a real one.  A label applied
to a whole axis rather than to a measured shape is exactly what
`arc3_taxonomy` declares `accounts=False`, and it had hidden four axes.

## A zero row count is not coverage on its own

The verdict table carries a **FACTS** column: the number of comparisons each
axis actually performed.  A hand-read "0 disagreements" says nothing about an
axis that compared nothing, and this project has been caught by checks that
reported success without verifying — so an axis whose fact count is 0 prints
`INERT`, is listed by name, and is a demand for a better probe rather than a
pass.  Measured over the full battery: 34,504 facts, no inert axis.

## Determinism

`rows.tsv` and `REPORT.txt` are byte-identical across `PYTHONHASHSEED=1` and
`PYTHONHASHSEED=12345`.  Every set reaches a row already sorted by its printed
form, because CPython randomises `set` iteration order per process and the
correct-path gem5 leg was bitten by exactly that — two byte-identical
measurements produced TSVs differing on 24 of 49 rows for no reason but the
hash seed.  A reference nobody can diff against the last run is a reference
nobody can check.

## Guests

`probes_wp_a64.py` generates guests whose wrong path is worth measuring.  The
correct-path probe set covers ISA classes on the *correct* path and is mostly
straight-line, so an axis can have no wrong-path instance of its fact at all.
Every class here sits in the **shadow of a conditional branch**:

| probe | what its shadow holds |
| --- | --- |
| `p_wpmem` | sub-word loads and stores, `ldp`/`stp`, NEON, scalar FP |
| `p_wpchain` | a chain of dependent loads, so the excursion's addresses depend on data the reconstruction had to get right |
| `p_wpsel` | `csel`/`csinc`/`csinv`/`csneg`/`cset`, `ccmp`/`ccmn`, the exclusive pair and the LSE atomics |
| `p_wpcache` | AArch64 cache maintenance — the class gem5 **panics** on |

Every probe works out of a fixed-address `.data` arena and never touches the
stack: gem5's SE-mode process loader and qemu-user lay the stack out
differently, so an address derived from SP would differ between the two runs
for reasons that have nothing to do with either tool.

Each shadow is followed by straight-line **filler**.  Without it the walker
runs off the end of `.text` within a couple of blocks and gem5 — whose SE mode
turns the guest's own `svc` into a process exit — can say nothing about the
rest, so the tail of every excursion would be a `GEM5-LIMIT` the probe itself
manufactured.

`p_wpcache` is kept deliberately.  The correct-path leg excludes AArch64 cache
maintenance outright because gem5 aborts on it; this leg does not, because an
excursion that aborts the reference is exactly the case where the reference's
silence must be NAMED rather than read as agreement, and a limit nobody has
watched fire is a limit nobody can check.  Its rows carry gem5's own text.

## Running

```sh
ninja -C /mnt/md0/QEMU/qemu/build contrib-plugins

python probes_wp_a64.py <outdir>/wpprobes
python ../probes/mkprobes_aarch64.py <outdir>/cpprobes

# no LD_LIBRARY_PATH, no CST_GEM5_PYLIB, no PYTHONHOME: run under the
# interpreter gem5 was built against and the harness works the loader path
# out for itself (see ../gem5_env.py for why the obvious remedy SIGSEGVs).
/home/maccoy-merrell/anaconda3/bin/python compare_wp_a64.py \
    --gem5-dir <gem5> --qemu <build>/qemu-aarch64 \
    --plugin <build>/contrib/plugins/libchampsim_tracer.so \
    --decode <build>/contrib/plugins/cst_decode \
    --wpdepth 32 --max 0 -o <out> --tsv <out>/rows.tsv <guest ELF> …

/home/maccoy-merrell/anaconda3/bin/python selftest_wp_a64.py \
    --gem5-dir <gem5> --qemu … --plugin … --decode … -o <out> <guest ELF> …
```

Exit status is the tool's own and must be taken from the process, never
through a pipe:

    0  WP-DEFECT + RECONSTRUCTION-GAP + UNACCOUNTED == 0 and the
       declared-vs-compared identity holds
    1  scored, and one of those is non-zero
    3  REFUSED — a prerequisite is absent, or gem5 did not run the CORRECT
       path to completion.  Nothing is scored.

The correct-path run is where the entry-state ground truth comes from, so it
is the one run this leg still refuses over: without it a `RECONSTRUCTION-GAP`
could not be told from a `WP-DEFECT`.  The **injected** runs are expected to
end abnormally — an excursion is not a program — so those are recorded with
their reason and their uncompared tail is charged to a named `GEM5-LIMIT`.

Author: Maccoy Merrell.
