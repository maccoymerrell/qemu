# mipsel register attribution -- the measured result

Run of 2026-08-22 against `champsim-trace` @ `5379a000ac`, method in
`METHOD.md`, per-opcode table at
`/mnt/md0/QEMU/cst_runs/_arc3_cov/mipsel/attrib.tsv` (977 rows; run outputs
live under `cst_runs`, not in the tree).  `RESULT_signatures.tsv` beside this
file is the signature summary as measured.

| | |
| --- | ---: |
| opcodes attempted | **977** |
| tracer set == adjudicated reference set | **730** |
| disagree | **247** |
| **unprobed** | **0** |

## Where the 247 come from

Only **13** rows disagree with rank 1 (LLVM MC) at all, and **11 of those 13
are LLVM defects the tracer already gets right**.  The other 234 are rows where
LLVM, Capstone and the tracer agree with each other and all three are wrong,
because no static mipsel reference models the state involved.

| rows | signature | what it is |
| ---: | --- | --- |
| 189 | `SRC-miss{FCSR} DST-miss{FCSR}` | FCSR / MSACSR on ordinary FP arithmetic. 108 helpers in `fpu_helper.c` call `update_fcr31()`, which does `SET_FP_CAUSE(fcr31)` unconditionally and reads `GET_FP_ENABLE(fcr31)` and the rounding mode; 50 MSA helpers reach `update_msacsr()`. `abs`/`neg`/`class`/`mov` and `fclass`/`fill` do not, and are excluded -- the class is derived from QEMU, not assumed. |
| 25 | `SRC-miss{SYS} DST-miss{SYS}` | The CP0 footprint of `syscall`, `break`, `sdbbp`, the twelve trap forms, `eret`/`deret`, `tlbr`/`tlbp`, `di`/`ei`, `dmt`/`emt`/`dvpe`/`evpe`. `set_EPC` (`system/tlb_helper.c:1421-1440`) writes `CP0_EPC`, `CP0_Cause.BD`, `CP0_Status.EXL` and reads `CP0_Status`. R5: a conditional trap still names the write. |
| 5 | `SRC-miss{SYS}` | `tlbwi`/`tlbwr`/`tlbinv`/`tlbinvf`/`wait` read CP0 and record nothing. |
| 22 | `*-miss{SYS,ACC,FPR,FCSR,FLAGS} *-extra{GPR}` | The MT ASE. `MFTR`/`MTTR`'s `(u, sel)` pair selects the register **file** of the far operand; all three decoders collapse the 24 named forms into one GPR<->GPR move. `mftgpr`/`mttgpr` genuinely are GPR<->GPR and do agree, so the rule is not failing the family wholesale. |
| 4 | `*-miss{LLBIT}` | The LL/SC link bit, recorded by neither side. |
| 2 | `SRC-miss{GPR}` | `lwle`/`lwre` merge into their destination; the tie is in LLVM's descriptor but not in the tracer. |

## Rows where the tracer is right and rank 1 is wrong

`bc1f`/`bc1t`/`bc1fl`/`bc1tl` (LLVM `Defs=[AT]`, a branch-expansion artifact),
`bposge32`/`rddsp`/`wrdsp`/`mthlip` (no DSPControl in LLVM's implicit lists),
`ctcmsa` (LLVM models the control register it writes as a use).

## Rulings made against a reference

* binutils' `WR_HI`/`WR_LO` on the DSP multiply-to-GPR forms (`mul.ph`,
  `mul_s.ph`, `muleq_s.w.ph[lr]`, `muleu_s.ph.qb[lr]`, `mulq_rs.ph`,
  `mulq_s.ph`) is a **hazard** annotation, not a dataflow write: QEMU writes
  only `cpu_gpr[ret]` and LLVM declares no implicit def.  Three sources against
  one; the tracer agrees with the adjudicated answer.
* `dmt`/`emt` are taken from the MT ASE definition rather than from QEMU,
  because `helper_dmt` is a `/* TODO */ return 0;` stub -- R6's premise does
  not hold there.  **Reported as a QEMU gap.**

## Model-level findings, not row disagreements

* **`FCC` is split from `FCSR`.**  `FCC0..7` are bits of `FCR31`, but the
  tracer names them `REG_PRED0..7` and `FCR31` `REG_FCSR`, so a `ctc1` to
  `FCR31` followed by a `bc1t` is a broken dependence.  Not counted, because
  the representative `cfc1`/`ctc1` encodings select `FCR5`, not `FCR31`, and
  both sides are right at the probed encoding.
* **`HI`/`LO` fold to `REG_ACC<n>`** and that is correct under R4: they are the
  two halves of the 64-bit DSP accumulator, a true hardware alias.  The
  consequence -- `mfhi` and `mflo` being indistinguishable in the dataflow --
  is R4's consequence, not a defect.

## How the measurement was checked

Falsification: all 730 agreeing rows perturbed, **730/730 flagged**.  Vacuous
agreement: exactly **1** row (`sync`, correctly empty).  C3 measured rather
than assumed: every free register-shaped field rewritten, **965/965** rows that
still decode to the same mnemonic have an invariant operand-set shape.  Two
independent tracer paths (`--hex` per encoding, and the `--batch` fields
columns added at `5379a000ac`), in two different binaries: **977/977
identical**.  Rank 1 vs rank 2: 153 binutils implied-register assertions
checked, 26 did not hold, all 26 adjudicated above.

A first pass silently lost 612 of 977 rows when the shared `build/` binary was
relinked mid-run.  It was caught because the pass counts its own rows; every
pass since snapshots the binary and asserts `rows == 977`.
