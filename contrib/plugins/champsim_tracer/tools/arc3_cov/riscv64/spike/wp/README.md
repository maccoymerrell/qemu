# riscv64 WRONG-PATH execution cross-check — ChampSim Tracer against Spike

`STATUS.md` and every gate this project runs compare correct path against
correct path.  **No WP golden exists on any ISA**, so a wrong-path divergence
has been invisible for the whole arc, and the wrong-path arm is a large
fraction of what the tracer emits.  This leg closes that hole by the method the
maintainer named:

> "Tools like Spike (unlike pin) are very useful, because they can also be used
> to validate the wrong-path execution by recreating the regfile contents the
> trace would have starting the wrong-path, then firing up spike at that PC
> with those reg + mem contents to see what it executes."

```
   trace ──► reconstructed regfile + memory ──► injected bare-metal ELF
                                                        │
                                                      spike
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

## The reconstruction, and why it is the interesting part

`format.rst` §5.4 says a consumer rebuilds the register file from the REGFILE
seed plus the DST_REG snapshots.  `wp_trace.py` performs exactly that
reconstruction; memory is rebuilt from three sources the wire states — the ELF
image, the datum every correct-path **load** returned, and the datum every
correct-path **store** wrote.  Three outcomes, kept strictly apart:

| verdict | meaning |
| --- | --- |
| `WP-DEFECT` | the excursion executed something the architecture would not, from a starting state the trace fully specified |
| `RECONSTRUCTION-GAP` | the trace does not carry enough state to rebuild the starting point — a finding about what the **wire** drops |
| `SPIKE-LIMIT` | the reference cannot state the fact.  `execute_insn_logged` prints a commit line only on completion, so a trapping instruction leaves no record at all |
| `TRACER-SUPERSET` | we record a fact the reference cannot, and a **named** rule from `arc3_rules.RISCV_EXEC` says why.  COVERED, not a defect |
| `UNACCOUNTED` | a disagreement nobody has explained.  MUST BE 0 |

The gap verdict is assigned from **evidence, never from plausibility**.  A
register is a gap only where the `wp-entry-state` axis measures the
reconstruction wrong against the correct-path run's own ground truth; an
address is a gap only where no ELF byte, no CP load datum and no CP store datum
ever established it.

## How the state gets into Spike

Spike has no "set the register file" interface, so the state is installed the
only way a machine accepts state: as instructions.  `wp_seed.py` emits a
bare-metal ELF whose entry point materialises every register the trace named
with `li` / `fmv.d.x` / `vle8.v`, points `mepc` at the excursion's first PC and
`mret`s into it.  `t0` is the prologue's scratch and is therefore written
**last**; the transfer is `mret`, which needs no register.

Costs, stated rather than hidden:

* the excursion retires in **M-mode**.  Every instruction the WP arm emits on
  this ISA is unprivileged, so the level changes no result — but this leg
  cannot check a privilege fault and does not claim to.
* the prologue itself retires and is excluded **by address**, never by count:
  it lives at `0x40000000` and the guest at its own link address.
* `vl`/`vtype` cannot be restored.  The tracer folds `vstart`, `vxsat`, `vxrm`,
  `vcsr`, `vl`, `vtype` and `vlenb` onto `REG_VCTRL`, and a fold is not
  invertible.  Reported as a seed gap on every excursion.

## The negative control is part of the result

`selftest_wp.py` breaks one fact on one side of a real aligned pair and
requires the axis that owns it to fire.  **Eleven** axes plus the injection
control, all firing, is the bar; an axis with no firing mutation reports
`UNPROVEN` and its zero is not counted as a pass.

The **injection control** is the load-bearing one: it perturbs the state that
is *installed* and requires the simulator's own execution to change.  Without
it, an agreement could mean the reconstruction is correct, or it could mean the
reconstruction never reached the simulator and the excursion followed the same
path regardless — indistinguishable from the comparison alone.

The control has already earned its keep twice.  It reported the memop axes as
having **no mutation at all** (the CP probe set is straight-line: five of its
seven guests kick no excursion, and the one that does had only a load where the
store-data mutation looked), which is why `probes_wp.py` exists.  And building
the entry-state ground truth exposed a defect in **this harness**: spike's
vector element read-back (`vectorUnit_t::elt` on the write path) logs
`read vN` carrying the **post**-write value, so treating every read as
pre-state evidence back-dated a vector register's final content to the start of
the run and manufactured 30 "reconstruction gaps" that were the harness's own
arithmetic.

## Guests

`probes_wp.py` generates guests whose wrong path is worth measuring.  The
correct-path probe set covers ISA classes on the *correct* path; measured at
`wpdepth=16` over its seven guests, `p_flow` contributes 19 excursions,
`p_atomic` 1, and the other five **none**.  `p_wpmem` puts sub-word loads and
stores, FP and RVV in the shadow of a conditional branch; `p_wpchain` puts a
dependent-load chain there, so the excursion's addresses depend on data the
reconstruction had to get right.

## Running

```sh
python compare_wp.py \
    --spike <patched spike> --pk <riscv-pk>/pk \
    --qemu <build>/qemu-riscv64 \
    --plugin <build>/contrib/plugins/libchampsim_tracer.so \
    --decode <build>/contrib/plugins/cst_decode \
    --dtc-dir <dir containing dtc> \
    --wpdepth 32 --max 0 -o <outdir> --tsv <rows.tsv> <guest ELF> ...

python selftest_wp.py  --spike … --qemu … --plugin … --decode … \
    --dtc-dir … --wpdepth 16 -o <outdir> <guest ELF> ...
```

Exit status is non-zero when `WP-DEFECT + RECONSTRUCTION-GAP + UNACCOUNTED` is
non-zero, and for the control when any attempted axis did not fire or the
injection control did not.

The reference must be the **patched** Spike (`../spike-patches/`);
`spike_ref.require_patched` refuses a log from a binary that is not, so a stale
binary reports as an error rather than as three axes quietly agreeing with
nothing.

Author: Maccoy Merrell.
