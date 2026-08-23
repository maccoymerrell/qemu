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

---

# Adjudication, and what it changed

Every signature above was adjudicated to one of TRACER DEFECT / REFERENCE
DEFECT / NOT-A-DISAGREEMENT / NEEDS-RULING, and the tracer defects were fixed
locally on the fork (R8) at the Capstone boundary, `disas/capstone.c`.
Re-measured with the same 977 rows and the same reference:

| | before | after |
| --- | ---: | ---: |
| tracer set == adjudicated reference set | **730** | **958** |
| disagree | **247** | **19** |
| distinct disagreement signatures | 16 | 3 |
| unprobed | 0 | 0 |

## TRACER DEFECT -- fixed (228 rows)

| rows | signature | fix | adjudicated by |
| ---: | --- | --- | --- |
| 189 | `SRC-miss{FCSR} DST-miss{FCSR}` | `cap_mips_fp_ctrl_reg` adds FCR31 / MSACSR to both lists | QEMU (R6); no static reference models it |
| 15 | `SRC-miss{SYS}` x5, part of `SRC-miss{SYS} DST-miss{SYS}` x10 | per-instruction CP0 footprint switch | QEMU's own helpers, register by register |
| 22 | the `B2-MTFILE` rows | `cap_mips_mt_far_reg` resolves the far operand's file from `(u, sel)` | QEMU `gen_mftr`/`gen_mttr` (R6) |
| 2 | `SRC-miss{GPRN}` (`lwle`/`lwre`) | added to the LWL/LWR partial-write id list | rank 1 (LLVM `TIED_TO`), confirmed in QEMU |

**FCR31 / MSACSR.**  `SET_FP_CAUSE` is a read-modify-write of the word
(`target/mips/cpu.h:83`) executed unconditionally inside `update_fcr31()`,
which then reads `GET_FP_ENABLE(fcr31)`; `update_msacsr()` is the same shape on
`env->active_tc.msacsr`.  Source *and* destination, on every member.  This is a
modelling gap in the decoder lineage, not a decode bug -- LLVM MC declares no
FP status register on MIPS arithmetic either -- so it will not go away on a
Capstone bump.  Over the 953 distinct mnemonics of the opcode space the two
predicates select exactly the 189 members: no false positive, no false
negative.  `abs.s` (`05290046`) is the negative control and stays empty.

**The CP0 footprint an instruction OWNS.**  Split out of the 25-row signature
deliberately: `tlbr`/`tlbp`/`tlbwi`/`tlbwr`/`tlbinv`/`tlbinvf`/`di`/`ei`/
`eret`/`deret`/`wait`/`dvpe`/`evpe`/`dmt`/`emt` have CP0 access as their entire
architectural effect, and QEMU's helpers name the registers one at a time
(`r4k_helper_tlbr` at `system/tlb_helper.c:240`, `helper_di`/`helper_ei` at
`system/special_helper.c:30`, `exception_return`, `helper_dvpe`/`evpe`).
Before the fix `eret` had no inputs and no outputs and `tlbwi` read nothing --
a kernel's whole TLB-refill path carried no dependency at all.

**The MT ASE.**  `(u, sel)` selects the register FILE of the far operand;
Capstone prints it as a GPR regardless, so `mftc0 $a0, $5` recorded a read of
`$a1` -- a register the instruction never touches -- and recorded the CP0
register it does read nowhere.  One fabricated dependency and one deleted one
out of a single wrong register class (C4).  `mftgpr`/`mttgpr` really are
GPR-to-GPR and are left alone.

## REFERENCE DEFECT -- corrected (0 rows moved)

`adjudicate.py`'s `mt_reg` computed the DSP accumulator index of an `MFTR` as
`rt & 3`.  It is `rt >> 2`: QEMU's `gen_mftr` spells the sixteen `rt` values
out one at a time and the `(lo, hi, acx)` group advances by four, so `rt`
4/5/6 are AC1, not AC0/AC1/AC2.  The old formula was right for the `mfthi`
representative and wrong for `mftlo` and `mftacx`; the MTTR side was already
algebraically correct.  No verdict moved -- the tracer was wrong either way --
but the corrected reference is what the fix had to satisfy.

## NEEDS-RULING (19 rows, all that remain)

* **The trap footprint (15 rows: `syscall`, `break`, `sdbbp`, the twelve trap
  forms).**  Does an instruction's register set include the CP0 state that the
  EXCEPTION it raises writes (EPC / Cause.BD / Status.EXL / BadInstr), given
  that under the same rule every faultable load and store would also read and
  write `REG_SYS`, and that in user mode -- where most mipsel tracing happens
  -- that write does not occur at all?  Deliberately NOT changed: the line the
  reference drew ("instructions whose only purpose is to trap") is a defensible
  choice but is not derivable from R1, under which a `teq` that does not fire
  writes exactly as much as an `lw` that does not fault.
* **The LL/SC link bit (4 rows: `ll`, `lle`, `sc`, `sce`).**  Should the tracer
  mint a generic register for load-linked/store-conditional reservation state?
  Measured cross-ISA context: no ISA models it today -- aarch64 `stlxr`
  (`5ffc0088`) and riscv64 `lr.w` (`2fa30210`) both report nothing for the
  monitor -- and `generic_ids.h`'s own policy says a new ID needs strong
  justification.  The existing representation is `CST_INSN_FLAG_ATOMIC` plus
  the boundary's promotion of `sc`'s `$rt` to READ|WRITE for the success bit.

## Further findings from the adjudication

* **`qemu_classes.py` does not reproduce this run's FCR31 class.**  Re-run
  against the same unchanged `target/mips` it emits **180** mnemonics where the
  run's `qemu_fcr31_class.json` holds **89**; the 91 extras are the `c.*.ps`
  paired-single compares, the r6 `cmp.*`/`maddf`/`max`/`rint` family and the
  MIPS-3D `recip1`/`rsqrt1` forms.  **No row moves**: every one of the 91 lies
  outside the 977-row mips32r2 opcode space, so `attrib.tsv` is unaffected and
  the byte-identical-outputs claim survives -- but `METHOD.md`'s statement that
  the run regenerates its class membership byte-identically is not true of that
  intermediate.  The boundary fix uses the regenerated (180) class, so it also
  covers r6 and MIPS-3D binaries the probe space does not reach.
* **QEMU gap: legacy `abs.fmt`/`neg.fmt` cannot signal Invalid.**  Pre-2008
  MIPS defines them as arithmetic instructions that signal Invalid Operation on
  an SNaN input; QEMU routes the non-`abs2008` case to
  `helper_float_abs_s(uint32_t)`, which takes no `CPUMIPSState` and therefore
  cannot touch FCR31 or raise.  Both sides of this measurement agree (neither
  names FCSR), so it is not a row disagreement, and the tracer is left matching
  the guest it traces.  Reported as a QEMU modelling gap, not laundered into a
  tracer limitation.
* **The `FCC`-vs-`FCSR` split is now partly bridged.**  With FCR31 on the
  compares, `ctc1 $rt,$f31` and a following `c.eq.s` do share an edge; the
  `bc1t` that consumes the condition still reads only `REG_PRED0`, so the
  model question stands.

## Re-measurement

Probe binary `9ca2da6f6d12b42b` (snapshotted, not the shared `build/` copy),
977/977 rows returned `fields ok=1`, `rows == 977` asserted before the output
was used.  Falsification of the new number: all **958** agreeing rows perturbed
(drop a source, plant a phantom destination), **958/958 flagged**.  Vacuous
agreement: **1** row (`sync`); 40 agree with an empty destination set -- the
stores, branches and prefetches, plus the five CP0 readers that write no
register.  Outputs in `/mnt/md0/QEMU/cst_runs/_arc3_cov/mipsel_fix/`.
