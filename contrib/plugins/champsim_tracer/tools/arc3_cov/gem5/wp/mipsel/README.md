# mipsel WRONG-PATH execution cross-check — ChampSim Tracer against gem5

`STATUS.md` and every gate this project runs compare correct path against
correct path.  **No WP golden exists on any ISA**, so a wrong-path divergence
was invisible for the whole arc, and the wrong-path arm is a large fraction of
what the tracer emits.  The riscv64 leg closed that hole against Spike; the
maintainer's direction for the remaining three ISAs is that their wrong paths
be verified by gem5, and this is the mipsel leg of it.

```
   trace ──► reconstructed regfile + memory ──► injected ELF32
                                                       │
                                                   gem5 MIPS SE
                                                       │
   the tracer's WP record ◄──── compared against ──── what the ISA does
```

## What an excursion is here

The unit is the whole WP **chain** hanging off one CP entry, not one WP block.
`emit_finalized_bb` kicks a single synchronous excursion that runs until the
`wpdepth` budget exhausts; the decoder renders it as `wp[0] wp[1] …` because a
chain is cut into basic blocks, not because each block is an independent event.
Comparing per block would compare N starting states the tracer never claimed.

The excursion's starting state is the architectural state at the **end of its
CP entry**: only correct-path effects update it.  A wrong-path write is
discarded by the machine when the excursion ends, so replaying one into the
shadow would seed the next excursion from a state that never existed.

## The reconstruction

`format.rst` §5.4 says a consumer rebuilds the register file from the REGFILE
seed plus the DST_REG snapshots.  `wp_trace.py` — shared with the riscv64 leg,
because it reads the wire and not an ISA — performs exactly that
reconstruction; memory is rebuilt from three sources the wire states: the ELF
image, the datum every correct-path **load** returned, and the datum every
correct-path **store** wrote.

| verdict | meaning |
| --- | --- |
| `WP-DEFECT` | the excursion recorded something the architecture would not, from a starting state the trace fully specified |
| `RECONSTRUCTION-GAP` | the trace does not carry enough state to rebuild the starting point — a finding about what the **wire** drops |
| `GEM5-LIMIT` | the reference cannot state the architectural fact: it is silent, or it states something the ISA does not have.  Named one by one with the observed text |
| `TRACER-SUPERSET` | we record a fact the reference cannot, and a **named** rule from `wp_rules_mipsel.MIPSEL_WP` says why.  COVERED, not a defect |
| `UNACCOUNTED` | a disagreement nobody has explained.  MUST BE 0 |

The gap verdict is assigned from **evidence, never from plausibility**.  A
register is a gap only where the `wp-entry-state` axis measures the
reconstruction wrong against the correct-path run's own ground truth; an
address only where no ELF byte, no CP load datum and no CP store datum ever
established it.

**A SUPERSET STILL HAS TO BE EARNED.**  gem5 already caught one mipsel tracer
defect on the correct path this arc — every conditional branch published a
phantom `REG_GPR1` (`$at`) destination, fixed at `95a0d89e92` — and it scored
`TRACER-SUPERSET` the entire time it was live, because the DIRECTION of a set
difference says nothing about whether the extra is TRUE.  A superset row with
no rule naming why the reference cannot state the fact is `UNACCOUNTED`, and
the run is red.

## How the state gets into gem5

gem5 in syscall-emulation mode loads an ELF and starts at `e_entry`; it has no
"set the register file" interface.  So the state is installed the only way a
machine accepts state: **as instructions**.  `wp_seed_mipsel.py` emits an ELF32
whose entry point materialises every register the trace named — the FP file
through `lwc1` from a table, `hi`/`lo` through `mthi`/`mtlo`, `fcsr` through
`ctc1`, the integer file through explicit `lui`/`ori` pairs — and then `j`s to
the excursion's first PC.

Costs, stated rather than hidden:

* `$at` (`$1`) is the prologue's scratch, so it is written **last**, and the
  transfer is a J-type `j`, which needs no register at all.  `j` takes its top
  four address bits from the delay slot's PC, so `build` **refuses** rather
  than emitting a jump to a silently different address when the prologue and
  the excursion are not in one 256 MB region.
* The prologue retires and is excluded **by address** — `[BOOT_BASE,
  BOOT_BASE+len)` — never by count.  gem5's `--maxinsts` is a bound only; the
  comparison walks the excursion's own length.
* `REG_PRED0` (the FP condition code) is published with **width 0**, a name
  with no value, so it cannot be installed.  Reported as a seed gap on every
  excursion.
* `REG_SYSID` (FIR) and `REG_SYSEXC` are read-only implementation state a
  user-mode prologue cannot write; reported as unmappable ids.

Two things that had to be measured rather than assumed, both of which produced
a **silent** wrong answer first:

* `objcopy -O binary` **without `-j .text`** emits `.reginfo`'s 24 bytes
  instead of the code, because a MIPS `.o` carries `.reginfo`,
  `.MIPS.abiflags` and `.pdr` alongside `.text`, all at VMA 0.  gem5 fetched
  them and died with `src/arch/mips/faults.cc:139: panic: Fault Reserved
  Instruction Fault` at tick 0, before a single line of trace.
* Every segment of the injected image is marked **R+W+X**, because
  `gem5_ref.parse` filters the reference stream to the executable ranges of
  the ELF it is handed and an excursion can reach an address the guest's own
  link put in a non-executable segment.  A filtered-out reference instruction
  reads as the reference's silence, i.e. as agreement.

## Adjudication is arithmetic where it can be

`REF-MIPS32-SIGNED-ON-ZEXT` is not a label asserted over a disagreement: the
harness recomputes the MIPS32 answer from the **reference's own** operand
values (`mips32_acc`) and reports which side the ISA agrees with.  Using the
tracer's operand values would beg the question the row asks.  A reference
value found wrong that way is then carried forward as a **taint**, so an
`mfhi`/`mthi` repeating it is charged to propagation rather than counted as a
second mechanism — and the taint is cleared the moment the two sides agree
about a write to that register, so it cannot outlive its cause.

## The negative control is part of the result

`selftest_wp_mipsel.py` breaks one fact on one side of a real aligned pair and
requires the axis that owns it to fire.  Twelve axes plus the **injection
control** is the bar; an axis with no firing mutation reports `UNPROVEN` and
its zero is not counted as a pass.

The injection control is the load-bearing one: it perturbs the state that is
*installed* and requires gem5's own execution to change.  Without it an
agreement could mean the reconstruction is correct, or it could mean the
reconstruction never reached the simulator and the excursion went the same way
regardless — indistinguishable from the comparison alone.

It has already earned its keep: it reported the memop, FP and accumulator axes
as having **no mutation available**, because only `p_flow` of the four
correct-path mipsel probes kicks an excursion at all and its shadow is
branches and one `jal`.  `probes_wp_mipsel.py` exists for exactly that reason.

## The declared/compared identity

The report prints, and asserts,

```
sum of uncompared tails  ==  declared - compared
```

so a declared-versus-compared gap can never sit unexplained.  The riscv64
leg's 287 was exactly the tails of its named reference-limit rows; this leg
asserts it rather than leaving it to be rediscovered.

## Running

```sh
ninja -C /mnt/md0/QEMU/qemu/build contrib-plugins

python probes_wp_mipsel.py <outdir>/wprobes
python ../../gem5/probes/mkprobes_mipsel.py <outdir>/probes    # p_flow

# no LD_LIBRARY_PATH, no CST_GEM5_PYLIB, no PYTHONHOME: run under the
# interpreter gem5 was built against and the harness works the loader path
# out for itself (see gem5/METHOD.md).
/home/maccoy-merrell/anaconda3/bin/python compare_wp_mipsel.py \
    --gem5-dir <gem5> --qemu <build>/qemu-mipsel \
    --plugin <build>/contrib/plugins/libchampsim_tracer.so \
    --decode <build>/contrib/plugins/cst_decode \
    --wpdepth 16 -o <outdir>/run --tsv <outdir>/rows.tsv \
    <outdir>/probes/p_flow <outdir>/wprobes/p_wp*

/home/maccoy-merrell/anaconda3/bin/python selftest_wp_mipsel.py \
    --gem5-dir <gem5> --qemu … --plugin … --decode … -o <outdir>/nc \
    <outdir>/probes/p_flow <outdir>/wprobes/p_wp*
```

Exit status is the process's own and must be taken from it, never through a
pipe:

* `0` — `WP-DEFECT + RECONSTRUCTION-GAP + UNACCOUNTED` is 0 and the identity
  holds; for the control, every attempted axis fired and so did the injection.
* `1` — scored, and the headline is non-zero.
* `3` — REFUSED: a prerequisite is absent, or gem5 did not run the correct
  path to completion.  Nothing was scored and no facet cell may be written.

Author: Maccoy Merrell.
