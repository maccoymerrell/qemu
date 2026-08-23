# ARC 3 register attribution -- mipsel, whole opcode space

Author: Maccoy Merrell.  Tree: /mnt/md0/QEMU/qemu, branch `champsim-trace`.

## The number, re-measured after R7.6 and R7.7

| | at 5379a000ac | after the fixes | at HEAD, R7.6/R7.7 applied |
| --- | ---: | ---: | ---: |
| opcodes attempted | 977 | 977 | **977** |
| tracer set == adjudicated reference set | 730 | 958 | **977** |
| disagree | 247 | 19 | **0** |
| **unprobed** | 0 | 0 | **0** |

The last column is the whole mipsel opcode space in agreement.  Its power is
measured, not assumed: perturbing each row's tracer set -- drop one source,
or plant a phantom destination where both sets are empty -- flags **977 of
977**, so the comparison is not agreeing by being blind.

Nineteen of the closing rows are the two rulings:

* **R7.6**, 15 rows (`break sdbbp syscall teq teqi tge tgei tgeiu tgeu tlt
  tlti tltiu tltu tne tnei`) -- a TRACER change.  The CP0 state the exception
  an instruction raises writes is in that instruction's set.
* **R7.7**, 4 rows (`ll lle sc sce`) -- a REFERENCE change.  There is no
  reservation-state register; the tracer was right and the reference's
  invented `REG_LLBIT` is retired.

The remaining 45 were reference staleness, not tracer defects: the
accumulator split (`REG_ACCHI<n>`), the CP0 split, and the FP/MSA control
split all landed in the tracer after the middle column was measured, and
`canon.py` still mapped their names to the pre-split ids.

## The number, as first measured

| | |
| --- | ---: |
| opcodes attempted | **977** |
| tracer set == adjudicated reference set | **730** |
| disagree | **247** |
| **unprobed** | **0** |

Denominator: `opcodes.tsv`, the 977-row mipsel opcode space built by `METHOD.md`
in this directory.  Every row was probed on both sides; no row is excluded, and
no row is counted as agreeing because it could not be reached.

## What is compared

For each opcode, one representative little-endian encoding, and two sets:

* **tracer** -- `isaxcheck --isa=mipsel --layer=fields`, whose `SRC{}`/`DST{}`
  are the tracer's own `InsnFields` through `decode_detail_to_generic()`, i.e.
  what the trace is actually built from, not the Capstone boundary behind it.
* **reference** -- the ranked mipsel reference set, adjudicated per row.

Both are canonicalised into the tracer's own generic register namespace before
comparison (`attrib/canon.py`), so a naming difference is never a disagreement.
Per **R4** a sub-register difference is not a disagreement either: `HI<n>` and
`LO<n>` are the two halves of the 64-bit accumulator `AC<n>` and both
canonicalise to `REG_ACC<n>`; LLVM's `D<n>_64` (FGR64) canonicalises to
`REG_FPR<n>`.  `REG_IP` is dropped on both sides.

**`REG_ZERO` is not.**  It used to be, symmetrically, and a symmetric
blindfold is still a blindfold: a fabricated write to `$zero` and a correct
absence of one compared equal.  R7.3 -- "REG_ZERO exists, so it should be
specified.  We should not be dropping reg zero." -- removed the suppression
from AArch64's reference in 7880bf6125, and this harness carried the same one
until it was removed here.  Removing it flagged exactly two rows, `div` and
`divu`, and both were real: see "What removing the suppression found" below.

## The references, in rank order

1. **LLVM MC 18.1.3**, subtarget `mips32r2` + the full ASE set the tracer's own
   `kIsaTable` mipsel row selects.  Walked at the **`MCInstrDesc`** level, not
   `MCInst`: for `LWL`/`LWR`/`MOVF` the disassembler leaves the `TIED_TO`
   operand unmaterialised, so a consumer that walks `MCInst::getNumOperands()`
   silently loses the read-modify-write edge.  Implicit use/def lists included.
2. **binutils 2.42 `opcodes/mips-opc.c`**, linked and queried, not transcribed:
   the `pinfo`/`pinfo2` implied-register flags of every matching row.
3. **sail-cheri-mips** -- **not available in this environment**.  Where it is
   the named authority (the LL/SC link bit) the claim is carried by QEMU
   instead; this is stated per rule below rather than hidden.

Plus **QEMU's own modelling (R6)** for the three classes the arc brief names as
having no static mipsel reference: the trap footprint, FCSR on ordinary FP
arithmetic, and DSPControl.

## Adjudication rules

Every departure from the rank-1 answer carries a rule id, recorded per row in
`attrib.tsv`.  Nothing is averaged.

| rule | opcodes | what it decides |
| --- | ---: | --- |
| `L-AT` | 4 | LLVM defect. `BC1F/BC1T/BC1FL/BC1TL` carry `Defs=[AT]`, an artifact of the assembler's branch expansion, not an architectural write (**R2**). binutils names no such write. Removed from the reference -- **the tracer was right**. |
| `L-DSPCTL` | 6 | LLVM defect. `BPOSGE32`/`RDDSP` read DSPControl, `WRDSP` writes it, `MTHLIP` reads and writes it; none appears in the `MCInstrDesc` implicit lists. Added -- **the tracer was right**. |
| `L-MSACTL` | 1 | LLVM defect. `CTCMSA` models the MSA control register as a USE; the instruction writes it (`helper_msa_ctcmsa` assigns `env->active_tc.msacsr`). Corrected -- **the tracer was right**. |
| `Q-FCR31` | 89 | QEMU truth. 108 helpers in `target/mips/tcg/fpu_helper.c` call `update_fcr31()`, which does `SET_FP_CAUSE(env->active_fpu.fcr31, ...)` unconditionally and reads `GET_FP_ENABLE(fcr31)` and the fcr31 rounding mode. `abs`/`neg`/`class`/the pure moves do not, and are correctly excluded. |
| `Q-MSACSR` | 100 | QEMU truth. 50 MSA float helpers in `msa_helper.c` reach `update_msacsr()` (call-graph closure over the `MSA_FLOAT_*` macros, which is how the compare helpers get there). `fclass`/`fill` do not, and are correctly excluded. |
| `Q-TRAP` | 14 | **R7.6** + QEMU truth. `set_EPC` (`tlb_helper.c:1420-1456`) reads `CP0_Status` -- the `EXL` gate on the whole write, then `BEV` for the vector -- and read-modify-writes it; read-modify-writes `CP0_Cause` for `BD` (:1427-1430) and for the exception code (`mips_cause_set_field`, :1456, a cmpxchg loop over the word, `internal.h:172`); writes `CP0_EPC` (:1422). Registers 12/13/14, so `REG_SYSEXC`; register 8 (`BadInstr`, :1043) is the same id. Per **R4** a conditional trap names the write as a candidate whether or not it fires. |
| `Q-TRAPD` | 1 | **R7.6** on the DEBUG entry path. `sdbbp` raises `EXCP_DBp` (`translate.c:13049`, `:13454`), not `EXCP_TRAP`, so it reaches `set_DEPC`/`enter_debug_mode` (`:1204-1233`): `CP0_Debug` read-modify-written, `CP0_DEPC` written, and the same `Status`-gated read-modify-write of `CP0_Cause`. `REG_SYSDBG` on top of `REG_SYSEXC`, and **not** `EPC`. It is the row that proves the CP0 split is doing work. |
| `Q-CP0` | 15 | QEMU truth. The TLB and CP0-control helpers name their registers exactly: `r4k_helper_tlbr` writes EntryHi/EntryLo0/EntryLo1/PageMask, `r4k_helper_tlbp` writes Index, `helper_di`/`helper_ei` read and write `CP0_Status`, `helper_dvpe`/`helper_evpe` read-modify-write `CP0_MVPControl`. |
| `R7.7-LL` | 4 | **R7.7**: there is NO reservation-state register. Reservation state is a product of the *instruction*, not of a register; `ll`/`lle`/`sc`/`sce` name their real registers only and the monitor is the consumer's to model. Consistent with **R2** (we record ARCHITECTURAL dependencies) and with the other two ISAs, where `stlxr` and `lr.w`/`sc.w` model no monitor either. The former `Q-LLBIT` rule invented `REG_LLBIT` off `env->lladdr`/`env->llval`, which is QEMU's *implementation* of the monitor. Removed -- **the tracer was right**. |
| `B2-MTFILE` | 24 | Rank 2 decides. The MT ASE `MFTR`/`MTTR` `(u, sel)` pair selects the register **file** of the far operand; binutils is the only reference that names it per form. LLVM, Capstone and the tracer collapse all 24 into one GPR<->GPR move (**C4**). |
| `R1-TIED` | 2 | Rank 1 decides. `LWLE`/`LWRE` merge into the destination, so the destination is also a source (**R5**/**C4**). |
| `B2-ACCHALF` | 2 | Rank 2 decides. LLVM's `MFHI_DSP`/`MFLO_DSP` take the accumulator PAIR as their operand class, so rank 1 names both halves; binutils names the half explicitly (`RD_HI` on `mfhi`, `RD_LO` on `mflo`) and QEMU agrees, reading `cpu_HI[acc]`/`cpu_LO[acc]` one at a time (`gen_HILO`, `translate.c:2891-2905`). Two references and the model against one operand class -- **the tracer was right**. The move-TO forms need no rule: LLVM names the single half there. |

### Rulings made against a reference

* **binutils `WR_HI`/`WR_LO` on the DSP multiply-to-GPR forms is overruled.**
  `mul.ph`, `mul_s.ph`, `muleq_s.w.ph[lr]`, `muleu_s.ph.qb[lr]`, `mulq_rs.ph`,
  `mulq_s.ph` carry the flag, but QEMU writes only `cpu_gpr[ret]`
  (`MUL_RETURN32_32_ph`), and LLVM declares no implicit def.  Those bits drive
  the assembler's mult/div **hazard** nop insertion, not a dataflow claim.
  Three sources against one; the tracer agrees with the adjudicated answer.
* **`dmt`/`emt` are taken from the MT ASE definition, not from QEMU.**
  `helper_dmt` is a `/* TODO */ return 0;` stub, so **R6**'s premise does not
  hold for it.  The architectural read-modify-write of `VPEControl` is used.
  This is a QEMU gap, reported as such.

## Verification of the measurement itself

* **Falsification.** All 730 agreeing rows were perturbed (drop one source, or
  plant a phantom destination where there is none) and re-compared: **730/730
  were flagged**.  The comparison cannot report agreement it has not checked.
* **Vacuous agreement.** Exactly **1** of the 730 agrees with both sets empty
  (`sync`, correctly empty); 35 agree with an empty destination set, all of them
  stores, branches and prefetches.
* **C3, measured rather than assumed.** For each opcode, every register-shaped
  field the decode pattern leaves free was rewritten to a fresh distinct value.
  969 opcodes have such a field; 965 still decode to the same mnemonic, and for
  **965/965** the tracer's operand-set shape is invariant under the permutation.
  Field genericity is a measured fact for this run, not a premise.
* **Two independent tracer paths.** The 977 rows were probed once with
  `--layer=fields --hex` (one process per encoding, binary `ca31c242...`) and
  again with the `--batch` fields columns added at tip `5379a000ac`
  (binary `e5a4a05f...`).  **977/977 identical.**
* **Rank-1 against rank-2.** 153 binutils implied-register assertions
  (`RD_HI`/`RD_LO`/`WR_HI`/`WR_LO`/`WR_$31`/`RD_$31`/`WR_CC`/`RD_CC`) were
  checked against the LLVM-derived reference.  26 did not hold; all 26 were
  adjudicated above (24 MT ASE file rows, and the DSP hazard-flag ruling).
* **Probe integrity.** A first pass silently lost 612 of 977 rows when the
  shared `build/` binary was relinked mid-run.  It was caught because the pass
  counts its own rows; every run since uses a snapshotted binary and asserts
  `rows == 977`.

## Findings that are not row disagreements

* **`FCC` is split from `FCSR` in the tracer's canonical model.** `FCC0..7` are
  bits of `FCR31`, but the tracer names them `REG_PRED0..7` while naming
  `FCR31` `REG_FCSR`.  A `ctc1` to `FCR31` followed by a `bc1t` is therefore a
  broken dependence.  It is not counted as a row disagreement because the
  representative `cfc1`/`ctc1` encodings select `FCR5`, not `FCR31`, so both
  sides are right at the probed encoding.  Affects `cfc1`, `ctc1`, `cftc1`,
  `cttc1` as a model question.
* **`rdhwr`'s representative encoding parks its destination on `$zero`.** It was
  re-probed with `rt=$a0` (`3be8047c`): the destination is attributed correctly
  (`REG_GPR4`).  No gap.  Since R7.3 it is also the positive control for
  `REG_ZERO` itself: it is the one row of the 977 whose sets name the id, both
  sides name it, and it agrees -- so the comparison is carrying the id rather
  than losing it somewhere quieter than the old `DROP` set.

## What removing the suppression found

Two rows, `div` and `divu`, and they are a **Capstone defect that is now fixed
at the boundary** rather than an adjudication -- there is no rule id for them
because after the fix they simply agree.

The classic `div rs, rt` / `divu rs, rt` have no destination register field:
bits 15:11 are architecturally zero and an encoding with them set does not
decode (`1a088500` is rejected; `1a008500` is `div $zero, $a0, $a1`).  But
Capstone's AsmString spells the destination literally, `"div\t$$zero, $rs,
$rt"`, and then materialises that literal as operand 0 -- a `MIPS_REG_ZERO`
carrying `CS_AC_WRITE`.  LLVM MC, whose table the string comes from, reads it
as text and reports `RD{rs,rt} WR{ac0}` with no `$0`.  `mult`/`multu`, spelled
without the literal, were always right.

`disas/capstone.c` drops that operand, gated on the accumulator write rather
than on the mnemonic, because MIPS R6 -- a mode `cap_mode_mips()` selects from
the guest ELF's `e_flags` -- redefines `DIV`/`DIVU` as genuine three-operand
instructions whose destination must survive.  Measured against Capstone
directly:

| mode | encoding | decode | operand 0 | implicit writes |
| --- | --- | --- | --- | --- |
| MIPS32R2 | `0085001a` | `div $zero, $a0, $a1` | `$zero` WRITE | `ac0` |
| MIPS32R6 | `0085001a` | does not decode | -- | -- |
| MIPS32R6 | `00a6209a` | `div $a0, $a1, $a2` | `$a0` WRITE | none |
| MIPS32R2 | `00a6209a` | does not decode | -- | -- |

so the gate separates the two forms exactly, and neither encoding is reachable
in the other's mode.

* **The built-in gate cannot see this class at all.**  `isaxcheck`'s comparison
  normaliser folds the architectural zero register out of both sides unless
  `--keep-zero` is passed, and no gate run passes it.  So `div`'s fabricated
  `$zero` destination produced no gate signature and never would have; the
  attribution harness found it only because R7.3 made this comparison stop
  doing the same thing.

## Reproduce

```sh
cd /mnt/md0/QEMU/cst_runs/_arc3_cov/mipsel/attrib
R=/mnt/md0/QEMU/cst_runs/_arc3_refs/mipsel/work
F='+mips32r2,+msa,+dsp,+dspr2,+dspr3,+fp64,+eva,+virt,+ginv,+crc,+abs2008,+nan2008,+mt,+mips3d'
awk -F'\t' 'NR>1{h=$3;print $1" "substr(h,7,2) substr(h,5,2) substr(h,3,2) substr(h,1,2)}' \
    ../opcodes.tsv > enc_word.txt
$R/llvm_probe --cpu=mips32r2 --feats="$F" < enc_word.txt > llvm_raw.txt
$R/binutils_probe                          < enc_word.txt > bu_raw.txt
awk -F'\t' 'NR>1{print $3}' ../opcodes.tsv | \
    /mnt/md0/QEMU/qemu/build/contrib/plugins/isaxcheck \
        --isa=mipsel --layer=fields --batch > batch_tip.tsv
python qemu_classes.py /mnt/md0/QEMU/qemu     # the R6 leg, out of QEMU's own C
python parse.py && python build_ref.py && python adjudicate.py && python emit.py
```

`qemu_classes.py`, `parse.py`, `canon.py`, `build_ref.py`, `adjudicate.py` and
`emit.py` are mirrored into the repo at
`contrib/plugins/champsim_tracer/tools/arc3_cov/mipsel/attrib/`.  Running that
mirrored copy from an empty directory reproduces `attrib.tsv` and
`attrib_signatures.tsv` byte-identically, including regenerating the FCR31 and
MSACSR class membership from the QEMU tree rather than reusing this run's.

## Outputs

* `attrib.tsv` -- 977 rows, one per opcode: verdict, signature, both sets, the
  four set differences, the adjudication rules applied, and both references'
  raw answers.
* `attrib_signatures.tsv` -- the 16 distinct disagreement signatures with counts
  and the opcodes in each.
