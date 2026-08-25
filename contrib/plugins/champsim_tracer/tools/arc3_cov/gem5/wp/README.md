# x86_64 WRONG-PATH execution cross-check — ChampSim Tracer against gem5

`STATUS.md` and every gate this project runs compare correct path against
correct path.  **No WP golden exists on any ISA**, so a wrong-path divergence
has been invisible for the whole arc — and on x86_64 the wrong-path arm is the
largest fraction of what the tracer emits.  The PIN reference used elsewhere in
this project is **explicitly not an execution reference for the wrong path**:
PIN observes what the machine really retired, and a wrong-path excursion is by
construction a path the machine did not take.

gem5 is neither PIN nor QEMU.  It decodes and executes x86-64 with its own
decoder and its own semantics, and in syscall-emulation mode it runs the SAME
static ELF the tracer traces.

```
   trace ──► reconstructed regfile + memory ──► injected static ELF
                                                        │
                                                   gem5 X86 SE
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
seed plus the DST_REG snapshots.  `wp_trace.py` (shared with the riscv64 leg)
performs exactly that; memory is rebuilt from three sources the wire states —
the ELF image, the datum every correct-path **load** returned, and the datum
every correct-path **store** wrote.

| verdict | meaning |
| --- | --- |
| `WP-DEFECT` | the excursion executed something the architecture would not, from a starting state the trace fully specified |
| `RECONSTRUCTION-GAP` | the trace does not carry enough state to rebuild the starting point — a finding about what the **wire** drops |
| `GEM5-LIMIT` | the reference cannot state the fact.  Named one by one, with the observed text, and never quoted as agreement |
| `TRACER-SUPERSET` | we record a fact the reference cannot, and a **named** rule from `x86_exec_rules.X86_EXEC` says why.  COVERED, not a defect |
| `UNACCOUNTED` | a disagreement nobody has explained.  MUST BE 0 |

The gap verdict is assigned from **evidence, never from plausibility**.  A
register is a gap only where the `wp-entry-state` axis measures the
reconstruction wrong against the correct-path run's own ground truth; an
address is a gap only where no ELF byte, no CP load datum and no CP store datum
ever established it.

## How the state gets into gem5

gem5 has no "set the register file" interface, so the state is installed the
only way a machine accepts state: as instructions.  `wp_seed_x86.py` emits a
static ELF whose entry point points `rsp` at a scratch stack inside the boot
region, installs RFLAGS through `push`/`popfq`, loads the x87 file with eight
`fldt`s **in reverse** (so that after eight pushes TOP is back where it
started and `st(i)` holds what the wire said), loads XMM0..15 with `movups`
from a table, writes every integer register except the scratch, writes the
scratch `rax` **last**, and transfers with a direct `jmp rel32` — an indirect
jump would need a register the prologue has already committed.

Costs, stated rather than hidden:

* the prologue retires and is excluded **by address**, never by count: it
  lives at `0x30000000` and the guest at its own link address.
* `REG_FCSR` folds the x87 control word, status word, tag word and MXCSR onto
  one id, and a fold is not invertible — neither the rounding mode nor the x87
  TOP field can be restored from the wire.  Reported as a seed gap on every
  excursion.
* segment bases, the control file and the debug file are CPL-0 state; nothing
  the prologue can execute installs them.

## Reference limitations, measured and named

Every one of these was found by running gem5, not assumed:

* **`syscall` is not retired through the trace.**  gem5 SE mode handles it in
  its own syscall emulation and the log ends at the instruction before.  Every
  uncompared tail in this leg is this one limit.
* **gem5's x87 file is backed by a 64-bit double.**  Its `FLD80` lowering is
  `ld t1 ; ld t2w ; cvtint_fp80`.  Confirmed per row rather than asserted:
  `x87_is_rounded` checks that the tracer's 80-bit datum really is gem5's
  64-bit one rounded — exponent `0x4050 − 16383 + 1023 = 0x450` and the
  mantissa's top 52 bits after the explicit leading one.
* **`fninit` is unimplemented** (`warn: instruction 'fninit' unimplemented`).
  Harmless here — the eight `fldt`s restore TOP either way — but it means this
  leg cannot clear the x87 tag word.
* **gem5 publishes an x87 status-word destination for `fabs`/`fchs` and not
  for `fadd`/`fmul`/`fsub`**, measured on the same run.
* **gem5 prints no encoding**, so the `insn-bits` axis the riscv64 leg scores
  becomes `insn-length` here — which on a variable-length ISA is the
  substantive question anyway.  Where neither the `rdip` fall-through nor a
  sequential successor gives a length, the row is a named limit.

## The negative control is part of the result

`selftest_wp_gem5.py` breaks one fact on one side of one real aligned pair and
requires the axis that owns it to fire.  **Eleven** axes plus the injection
control, all firing, is the bar; an axis with no firing mutation reports
`UNPROVEN` and its zero is not counted as a pass.

The **injection control** is the load-bearing one: it perturbs the state that
is *installed* and requires gem5's own execution to change.  Without it, an
agreement could mean the reconstruction is correct, or it could mean the
reconstruction never reached the simulator and the excursion followed the same
path regardless — indistinguishable from the comparison alone.

## The declared/compared identity

The report prints, and the exit status enforces,

    sum of uncompared tails  ==  declared - compared

so a declared-versus-compared gap can never sit unexplained.

## Running

```sh
./REPRODUCE.sh                     # control first, then the comparison
```

Exit status is non-zero when `WP-DEFECT + RECONSTRUCTION-GAP + UNACCOUNTED` is
non-zero, or when the identity does not hold; and for the control when any
attempted axis did not fire or the injection control did not.

`gem5_env` refuses to start rather than segfault: `gem5.opt` names
`libpython3.11.so.1.0` in `DT_NEEDED` with no `RUNPATH`, and exposing the whole
Anaconda `lib` puts its older `libstdc++` in front of the one gem5 was compiled
against and kills it.  A shim directory holding exactly that one symlink is
used instead.

Author: Maccoy Merrell.
